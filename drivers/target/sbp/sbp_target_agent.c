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

static int tgt_agent_rw_agent_state(struct fw_card *card, int tcode, void *data,
		struct sbp_target_agent *agent)
{
	__be32 state;

	switch (tcode) {
	case TCODE_READ_QUADLET_REQUEST:
		pr_debug("tgt_agent AGENT_STATE READ\n");

		spin_lock_bh(&agent->lock);
		state = cpu_to_be32(agent->state);
		spin_unlock_bh(&agent->lock);
		memcpy(data, &state, sizeof(state));

		return RCODE_COMPLETE;

	case TCODE_WRITE_QUADLET_REQUEST:
		/* ignored */
		return RCODE_COMPLETE;

	default:
		return RCODE_TYPE_ERROR;
	}
}

static int tgt_agent_rw_agent_reset(struct fw_card *card, int tcode, void *data,
		struct sbp_target_agent *agent)
{
	switch (tcode) {
	case TCODE_WRITE_QUADLET_REQUEST:
		pr_debug("tgt_agent AGENT_RESET\n");
		spin_lock_bh(&agent->lock);
		agent->state = AGENT_STATE_RESET;
		spin_unlock_bh(&agent->lock);
		return RCODE_COMPLETE;

	default:
		return RCODE_TYPE_ERROR;
	}
}

static int tgt_agent_rw_orb_pointer(struct fw_card *card, int tcode, void *data,
		struct sbp_target_agent *agent)
{
	struct sbp2_pointer *ptr = data;

	switch (tcode) {
	case TCODE_WRITE_BLOCK_REQUEST:
		spin_lock_bh(&agent->lock);
		if (agent->state != AGENT_STATE_SUSPENDED &&
				agent->state != AGENT_STATE_RESET) {
			spin_unlock_bh(&agent->lock);
			pr_notice("Ignoring ORB_POINTER write while active.\n");
			return RCODE_CONFLICT_ERROR;
		}
		agent->state = AGENT_STATE_ACTIVE;
		spin_unlock_bh(&agent->lock);

		agent->orb_pointer = sbp2_pointer_to_addr(ptr);
		agent->doorbell = false;

		pr_debug("tgt_agent ORB_POINTER write: 0x%llx\n",
				agent->orb_pointer);

		queue_work(system_unbound_wq, &agent->work);

		return RCODE_COMPLETE;

	case TCODE_READ_BLOCK_REQUEST:
		pr_debug("tgt_agent ORB_POINTER READ\n");
		spin_lock_bh(&agent->lock);
		addr_to_sbp2_pointer(agent->orb_pointer, ptr);
		spin_unlock_bh(&agent->lock);
		return RCODE_COMPLETE;

	default:
		return RCODE_TYPE_ERROR;
	}
}

static int tgt_agent_rw_doorbell(struct fw_card *card, int tcode, void *data,
		struct sbp_target_agent *agent)
{
	switch (tcode) {
	case TCODE_WRITE_QUADLET_REQUEST:
		spin_lock_bh(&agent->lock);
		if (agent->state != AGENT_STATE_SUSPENDED) {
			spin_unlock_bh(&agent->lock);
			pr_debug("Ignoring DOORBELL while active.\n");
			return RCODE_CONFLICT_ERROR;
		}
		agent->state = AGENT_STATE_ACTIVE;
		spin_unlock_bh(&agent->lock);

		agent->doorbell = true;

		pr_debug("tgt_agent DOORBELL\n");

		queue_work(system_unbound_wq, &agent->work);

		return RCODE_COMPLETE;

	case TCODE_READ_QUADLET_REQUEST:
		return RCODE_COMPLETE;

	default:
		return RCODE_TYPE_ERROR;
	}
}

static int tgt_agent_rw_unsolicited_status_enable(struct fw_card *card,
		int tcode, void *data, struct sbp_target_agent *agent)
{
	switch (tcode) {
	case TCODE_WRITE_QUADLET_REQUEST:
		pr_debug("tgt_agent UNSOLICITED_STATUS_ENABLE\n");
		/* ignored as we don't send unsolicited status */
		return RCODE_COMPLETE;

	case TCODE_READ_QUADLET_REQUEST:
		return RCODE_COMPLETE;

	default:
		return RCODE_TYPE_ERROR;
	}
}

static void tgt_agent_rw(struct fw_card *card, struct fw_request *request,
		int tcode, int destination, int source, int generation,
		unsigned long long offset, void *data, size_t length,
		void *callback_data)
{
	struct sbp_target_agent *agent = callback_data;
	struct sbp_session *sess = agent->login->sess;
	int sess_gen, sess_node, rcode;

	spin_lock_bh(&sess->lock);
	sess_gen = sess->generation;
	sess_node = sess->node_id;
	spin_unlock_bh(&sess->lock);

	if (generation != sess_gen) {
		pr_notice("ignoring request with wrong generation\n");
		rcode = RCODE_TYPE_ERROR;
		goto out;
	}

	if (source != sess_node) {
		pr_notice("ignoring request from foreign node (%x != %x)\n",
				source, sess_node);
		rcode = RCODE_TYPE_ERROR;
		goto out;
	}

	/* turn offset into the offset from the start of the block */
	offset -= agent->handler.offset;

	if (offset == 0x00 && length == 4) {
		/* AGENT_STATE */
		rcode = tgt_agent_rw_agent_state(card, tcode, data, agent);
	} else if (offset == 0x04 && length == 4) {
		/* AGENT_RESET */
		rcode = tgt_agent_rw_agent_reset(card, tcode, data, agent);
	} else if (offset == 0x08 && length == 8) {
		/* ORB_POINTER */
		rcode = tgt_agent_rw_orb_pointer(card, tcode, data, agent);
	} else if (offset == 0x10 && length == 4) {
		/* DOORBELL */
		rcode = tgt_agent_rw_doorbell(card, tcode, data, agent);
	} else if (offset == 0x14 && length == 4) {
		/* UNSOLICITED_STATUS_ENABLE */
		rcode = tgt_agent_rw_unsolicited_status_enable(card, tcode,
				data, agent);
	} else {
		rcode = RCODE_ADDRESS_ERROR;
	}

out:
	fw_send_response(card, request, rcode);
}

static void tgt_agent_process_work(struct work_struct *work)
{
	struct sbp_target_request *req =
		container_of(work, struct sbp_target_request, work);

	pr_debug("tgt_orb ptr:0x%llx next_ORB:0x%llx data_descriptor:0x%llx misc:0x%x\n",
			req->orb_pointer,
			sbp2_pointer_to_addr(&req->orb.next_orb),
			sbp2_pointer_to_addr(&req->orb.data_descriptor),
			be32_to_cpu(req->orb.misc));

	if (req->orb_pointer >> 32)
		pr_debug("ORB with high bits set\n");

	switch (ORB_REQUEST_FORMAT(be32_to_cpu(req->orb.misc))) {
		case 0:/* Format specified by this standard */
			sbp_handle_command(req);
			return;
		case 1: /* Reserved for future standardization */
		case 2: /* Vendor-dependent */
			req->status.status |= cpu_to_be32(
					STATUS_BLOCK_RESP(
						STATUS_RESP_REQUEST_COMPLETE) |
					STATUS_BLOCK_DEAD(0) |
					STATUS_BLOCK_LEN(1) |
					STATUS_BLOCK_SBP_STATUS(
						SBP_STATUS_REQ_TYPE_NOTSUPP));
			sbp_send_status(req);
			sbp_free_request(req);
			return;
		case 3: /* Dummy ORB */
			req->status.status |= cpu_to_be32(
					STATUS_BLOCK_RESP(
						STATUS_RESP_REQUEST_COMPLETE) |
					STATUS_BLOCK_DEAD(0) |
					STATUS_BLOCK_LEN(1) |
					STATUS_BLOCK_SBP_STATUS(
						SBP_STATUS_DUMMY_ORB_COMPLETE));
			sbp_send_status(req);
			sbp_free_request(req);
			return;
		default:
			BUG();
	}
}

/* used to double-check we haven't been issued an AGENT_RESET */
static inline bool tgt_agent_check_active(struct sbp_target_agent *agent)
{
	bool active;

	spin_lock_bh(&agent->lock);
	active = (agent->state == AGENT_STATE_ACTIVE);
	spin_unlock_bh(&agent->lock);

	return active;
}

static void tgt_agent_fetch_work(struct work_struct *work)
{
	struct sbp_target_agent *agent =
		container_of(work, struct sbp_target_agent, work);
	struct sbp_session *sess = agent->login->sess;
	struct sbp_target_request *req;
	int ret;
	bool doorbell = agent->doorbell;
	u64 next_orb = agent->orb_pointer;

	while (next_orb && tgt_agent_check_active(agent)) {
		req = kzalloc(sizeof(*req), GFP_KERNEL);
		if (!req) {
			spin_lock_bh(&agent->lock);
			agent->state = AGENT_STATE_DEAD;
			spin_unlock_bh(&agent->lock);
			return;
		}

		req->login = agent->login;
		req->orb_pointer = next_orb;

		req->status.status = cpu_to_be32(STATUS_BLOCK_ORB_OFFSET_HIGH(
					req->orb_pointer >> 32));
		req->status.orb_low = cpu_to_be32(
				req->orb_pointer & 0xfffffffc);

		/* read in the ORB */
		ret = sbp_run_transaction(sess->card, TCODE_READ_BLOCK_REQUEST,
				sess->node_id, sess->generation, sess->speed,
				req->orb_pointer, &req->orb, sizeof(req->orb));
		if (ret != RCODE_COMPLETE) {
			pr_debug("tgt_orb fetch failed: %x\n", ret);
			req->status.status |= cpu_to_be32(
					STATUS_BLOCK_SRC(
						STATUS_SRC_ORB_FINISHED) |
					STATUS_BLOCK_RESP(
						STATUS_RESP_TRANSPORT_FAILURE) |
					STATUS_BLOCK_DEAD(1) |
					STATUS_BLOCK_LEN(1) |
					STATUS_BLOCK_SBP_STATUS(
						SBP_STATUS_UNSPECIFIED_ERROR));
			spin_lock_bh(&agent->lock);
			agent->state = AGENT_STATE_DEAD;
			spin_unlock_bh(&agent->lock);

			sbp_send_status(req);
			sbp_free_request(req);
			return;
		}

		/* check the next_ORB field */
		if (be32_to_cpu(req->orb.next_orb.high) & 0x80000000) {
			next_orb = 0;
			req->status.status |= cpu_to_be32(STATUS_BLOCK_SRC(
						STATUS_SRC_ORB_FINISHED));
		} else {
			next_orb = sbp2_pointer_to_addr(&req->orb.next_orb);
			req->status.status |= cpu_to_be32(STATUS_BLOCK_SRC(
						STATUS_SRC_ORB_CONTINUING));
		}

		if (tgt_agent_check_active(agent) && !doorbell) {
			INIT_WORK(&req->work, tgt_agent_process_work);
			queue_work(system_unbound_wq, &req->work);
		} else {
			/* don't process this request, just check next_ORB */
			sbp_free_request(req);
		} 

		spin_lock_bh(&agent->lock);
		doorbell = agent->doorbell = false;

		/* check if we should carry on processing */
		if (next_orb)
			agent->orb_pointer = next_orb;
		else
			agent->state = AGENT_STATE_SUSPENDED;

		spin_unlock_bh(&agent->lock);
	};
}

struct sbp_target_agent *sbp_target_agent_register(
		struct sbp_login_descriptor *login)
{
	struct sbp_target_agent *agent;
	int ret;

	agent = kmalloc(sizeof(*agent), GFP_KERNEL);
	if (!agent)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&agent->lock);

	agent->handler.length = 0x20;
	agent->handler.address_callback = tgt_agent_rw;
	agent->handler.callback_data = agent;

	agent->login = login;
	agent->state = AGENT_STATE_RESET;
	INIT_WORK(&agent->work, tgt_agent_fetch_work);
	agent->orb_pointer = 0;
	agent->doorbell = false;

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
	fw_core_remove_address_handler(&agent->handler);
	cancel_work_sync(&agent->work);
	kfree(agent);
}
