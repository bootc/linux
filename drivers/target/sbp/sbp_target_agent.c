/*
 * SBP2 target driver (SCSI over IEEE1394 in target mode)
 *
 * Copyright (C) 2011  Chris Boot <bootc@bootc.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define KMSG_COMPONENT "sbp_target"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/firewire.h>
#include <linux/firewire-constants.h>
#include <linux/slab.h>

#include <target/target_core_base.h>

#include "sbp_base.h"
#include "sbp_management_agent.h"
#include "sbp_login.h"
#include "sbp_target_agent.h"
#include "sbp_scsi_cmnd.h"
#include "sbp_util.h"

static int tgt_agent_rw_agent_state(struct fw_card *card,
	int tcode, int generation, void *data,
	struct sbp_target_agent *agent)
{
	if (tcode == TCODE_READ_QUADLET_REQUEST) {
		__be32 state;

		pr_notice("tgt_agent AGENT_STATE READ");

		state = cpu_to_be32(atomic_read(&agent->state));
		memcpy(data, &state, sizeof(state));

		return RCODE_COMPLETE;
	} else if (tcode == TCODE_WRITE_QUADLET_REQUEST)
		/* ignored */
		return RCODE_COMPLETE;
	else
		return RCODE_TYPE_ERROR;
}

static int tgt_agent_rw_agent_reset(struct fw_card *card,
	int tcode, int generation, void *data,
	struct sbp_target_agent *agent)
{
	if (tcode == TCODE_WRITE_QUADLET_REQUEST) {
		pr_debug("tgt_agent AGENT_RESET");
		atomic_set(&agent->state, AGENT_STATE_RESET);
		return RCODE_COMPLETE;
	} else
		return RCODE_TYPE_ERROR;
}

static int tgt_agent_rw_orb_pointer(struct fw_card *card,
	int tcode, int generation, void *data,
	struct sbp_target_agent *agent)
{
	struct sbp2_pointer *ptr = data;

	if (tcode == TCODE_WRITE_BLOCK_REQUEST) {
		int ret;

		smp_wmb();
		atomic_cmpxchg(&agent->state,
			AGENT_STATE_RESET, AGENT_STATE_SUSPENDED);
		smp_wmb();
		if (atomic_cmpxchg(&agent->state,
			AGENT_STATE_SUSPENDED, AGENT_STATE_ACTIVE) !=
			AGENT_STATE_SUSPENDED)
			return RCODE_CONFLICT_ERROR;
		smp_wmb();

		agent->orb_pointer = sbp2_pointer_to_addr(ptr);

		ret = queue_work(fw_workqueue, &agent->work);
		if (!ret)
			return RCODE_CONFLICT_ERROR;

		return RCODE_COMPLETE;
	} else if (tcode == TCODE_READ_BLOCK_REQUEST) {
		pr_notice("tgt_agent ORB_POINTER READ");
		addr_to_sbp2_pointer(agent->orb_pointer, ptr);
		return RCODE_COMPLETE;
	} else
		return RCODE_TYPE_ERROR;
}

static int tgt_agent_rw_doorbell(struct fw_card *card,
	int tcode, int generation, void *data,
	struct sbp_target_agent *agent)
{
	if (tcode == TCODE_WRITE_QUADLET_REQUEST) {
		int ret;

		smp_wmb();
		if (atomic_cmpxchg(&agent->state,
			AGENT_STATE_SUSPENDED, AGENT_STATE_ACTIVE) !=
			AGENT_STATE_SUSPENDED)
			return RCODE_CONFLICT_ERROR;
		smp_wmb();

		pr_notice("tgt_agent DOORBELL");

		ret = queue_work(fw_workqueue, &agent->work);
		if (!ret)
			return RCODE_CONFLICT_ERROR;

		return RCODE_COMPLETE;
	} else if (tcode == TCODE_READ_QUADLET_REQUEST)
		return RCODE_COMPLETE;
	else
		return RCODE_TYPE_ERROR;
}

static int tgt_agent_rw_unsolicited_status_enable(struct fw_card *card,
	int tcode, int generation, void *data,
	struct sbp_target_agent *agent)
{
	if (tcode == TCODE_WRITE_QUADLET_REQUEST) {
		pr_notice("tgt_agent UNSOLICITED_STATUS_ENABLE");
		atomic_set(&agent->login->unsolicited_status_enable, 1);
		return RCODE_COMPLETE;
	} else if (tcode == TCODE_READ_QUADLET_REQUEST)
		return RCODE_COMPLETE;
	else
		return RCODE_TYPE_ERROR;
}

static void tgt_agent_rw(struct fw_card *card,
	struct fw_request *request, int tcode, int destination, int source,
	int generation, unsigned long long offset, void *data, size_t length,
	void *callback_data)
{
	struct sbp_target_agent *agent = callback_data;
	int rcode = RCODE_ADDRESS_ERROR;

	/* turn offset into the offset from the start of the block */
	offset -= agent->handler.offset;

	/* check the source matches the login */
	if (source != agent->login->sess->node_id) {
		pr_warn("tgt_agent request from different node (%x != %x)\n",
			source, agent->login->sess->node_id);
		fw_send_response(card, request, RCODE_TYPE_ERROR);
		return;
	}

	if (offset == 0x00 && length == 4) {
		/* AGENT_STATE */
		rcode = tgt_agent_rw_agent_state(card, tcode,
			generation, data, agent);
	} else if (offset == 0x04 && length == 4) {
		/* AGENT_RESET */
		rcode = tgt_agent_rw_agent_reset(card, tcode,
			generation, data, agent);
	} else if (offset == 0x08 && length == 8) {
		/* ORB_POINTER */
		rcode = tgt_agent_rw_orb_pointer(card, tcode,
			generation, data, agent);
	} else if (offset == 0x10 && length == 4) {
		/* DOORBELL */
		rcode = tgt_agent_rw_doorbell(card, tcode,
			generation, data, agent);
	} else if (offset == 0x14 && length == 4) {
		/* UNSOLICITED_STATUS_ENABLE */
		rcode = tgt_agent_rw_unsolicited_status_enable(card, tcode,
			generation, data, agent);
	}

	fw_send_response(card, request, rcode);
}

static void tgt_agent_process_work(struct work_struct *work)
{
	struct sbp_target_request *req =
		container_of(work, struct sbp_target_request, work);

	switch (ORB_REQUEST_FORMAT(be32_to_cpu(req->orb.misc))) {
	case 0:/* Format specified by this standard */
		sbp_handle_command(req);
		return;
	case 1: /* Reserved for future standardization */
	case 2: /* Vendor-dependent */
		req->status.status |= cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_DEAD(0) |
			STATUS_BLOCK_LEN(1) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_REQ_TYPE_NOTSUPP));
		sbp_send_status(req);
		sbp_free_request(req);
		return;
	case 3: /* Dummy ORB */
		req->status.status |= cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_DEAD(0) |
			STATUS_BLOCK_LEN(1) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_DUMMY_ORB_COMPLETE));
		sbp_send_status(req);
		sbp_free_request(req);
		return;
	default:
		BUG();
	}
}

static void tgt_agent_fetch_work(struct work_struct *work)
{
	struct sbp_target_agent *agent =
		container_of(work, struct sbp_target_agent, work);
	struct sbp_session *sess = agent->login->sess;
	struct sbp_target_request *req;
	int ret;

	smp_rmb();
	if (atomic_read(&agent->state) != AGENT_STATE_ACTIVE)
		return;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		goto out;

	smp_rmb();
	if (atomic_read(&agent->state) != AGENT_STATE_ACTIVE) {
		sbp_free_request(req);
		return;
	}

	/* read in the ORB */
	ret = fw_run_transaction(sess->card, TCODE_READ_BLOCK_REQUEST,
		sess->node_id, sess->generation, sess->speed,
		agent->orb_pointer, &req->orb, sizeof(req->orb));
	if (ret != RCODE_COMPLETE) {
		pr_err("tgt_orb fetch failed: %x\n", ret);
		sbp_free_request(req);
		goto out;
	}

	smp_rmb();
	if (atomic_read(&agent->state) != AGENT_STATE_ACTIVE) {
		sbp_free_request(req);
		return;
	}

	req->agent = agent;
	req->orb_pointer = agent->orb_pointer;

	pr_debug("tgt_orb ptr:0x%llx next_orb:0x%llx data_descriptor:0x%llx "
		"misc:0x%x\n", req->orb_pointer,
		sbp2_pointer_to_addr(&req->orb.next_orb),
		sbp2_pointer_to_addr(&req->orb.data_descriptor),
		be32_to_cpu(req->orb.misc));

	if (be32_to_cpu(req->orb.next_orb.high) & 0x80000000)
		req->status.status = cpu_to_be32(
			STATUS_BLOCK_SRC(STATUS_SRC_ORB_FINISHED));
	else
		req->status.status = cpu_to_be32(
			STATUS_BLOCK_SRC(STATUS_SRC_ORB_CONTINUING));

	req->status.status |= cpu_to_be32(
		STATUS_BLOCK_ORB_OFFSET_HIGH(agent->orb_pointer >> 32));
	req->status.orb_low = cpu_to_be32(agent->orb_pointer & 0xfffffffc);
	INIT_WORK(&req->work, tgt_agent_process_work);

	ret = queue_work(fw_workqueue, &req->work);
	if (!ret) {
		pr_err("tgt_orb queue_work failed\n");
		sbp_free_request(req);
	}

	/* check if we should carry on processing */
	if (be32_to_cpu(req->orb.next_orb.high) & 0x80000000) {
		/* null next_orb */
		goto out;
	}

	smp_rmb();
	if (atomic_read(&agent->state) != AGENT_STATE_ACTIVE)
		return;

	agent->orb_pointer = sbp2_pointer_to_addr(&req->orb.next_orb);

	if (!queue_work(fw_workqueue, &agent->work)) {
		pr_err("tgt_orb fetch queue_work failed\n");
		goto out;
	}

	return;

out:
	/* finished */
	atomic_cmpxchg(&agent->state,
		AGENT_STATE_ACTIVE, AGENT_STATE_SUSPENDED);
}

struct sbp_target_agent *sbp_target_agent_register(
		struct sbp_login_descriptor *login)
{
	struct sbp_target_agent *agent;
	int ret;

	agent = kmalloc(sizeof(*agent), GFP_KERNEL);
	if (!agent)
		return ERR_PTR(-ENOMEM);

	agent->handler.length = 0x20;
	agent->handler.address_callback = tgt_agent_rw;
	agent->handler.callback_data = agent;

	agent->login = login;
	atomic_set(&agent->state, AGENT_STATE_RESET);
	INIT_WORK(&agent->work, tgt_agent_fetch_work);
	agent->orb_pointer = (u64)-1;

	ret = fw_core_add_address_handler(&agent->handler,
		&sbp_register_region);
	if (ret < 0) {
		kfree(agent);
		return ERR_PTR(ret);
	}

	return agent;
}

void sbp_target_agent_unregister(struct sbp_target_agent *agent)
{
	if (atomic_read(&agent->state) == AGENT_STATE_ACTIVE)
		flush_work_sync(&agent->work);

	fw_core_remove_address_handler(&agent->handler);
	kfree(agent);
}

