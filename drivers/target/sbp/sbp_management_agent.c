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
#include <linux/kref.h>

#include <target/target_core_base.h>

#include "sbp_base.h"
#include "sbp_management_agent.h"
#include "sbp_login.h"
#include "sbp_scsi_cmnd.h"

static void sbp_mgt_agent_process(struct work_struct *work)
{
	struct sbp_management_agent *agent =
		container_of(work, struct sbp_management_agent, work);
	struct sbp_management_request *req = agent->request;
	int ret;
	int status_data_len = 0;

	/* fetch the ORB from the initiator */
	ret = sbp_run_transaction(req->card, TCODE_READ_BLOCK_REQUEST,
		req->node_addr, req->generation, req->speed,
		agent->orb_offset, &req->orb, sizeof(req->orb));
	if (ret != RCODE_COMPLETE) {
		pr_debug("mgt_orb fetch failed: %x\n", ret);
		goto out;
	}

	pr_debug("mgt_orb ptr1:0x%llx ptr2:0x%llx misc:0x%x len:0x%x status_fifo:0x%llx\n",
		sbp2_pointer_to_addr(&req->orb.ptr1),
		sbp2_pointer_to_addr(&req->orb.ptr2),
		be32_to_cpu(req->orb.misc), be32_to_cpu(req->orb.length),
		sbp2_pointer_to_addr(&req->orb.status_fifo));

	if (!ORB_NOTIFY(be32_to_cpu(req->orb.misc)) ||
		ORB_REQUEST_FORMAT(be32_to_cpu(req->orb.misc)) != 0) {
		pr_err("mgt_orb bad request\n");
		goto out;
	}

	switch (MANAGEMENT_ORB_FUNCTION(be32_to_cpu(req->orb.misc))) {
	case MANAGEMENT_ORB_FUNCTION_LOGIN:
		sbp_management_request_login(agent, req, &status_data_len);
		break;

	case MANAGEMENT_ORB_FUNCTION_QUERY_LOGINS:
		sbp_management_request_query_logins(agent, req,
				&status_data_len);
		break;

	case MANAGEMENT_ORB_FUNCTION_RECONNECT:
		sbp_management_request_reconnect(agent, req, &status_data_len);
		break;

	case MANAGEMENT_ORB_FUNCTION_SET_PASSWORD:
		pr_notice("SET PASSWORD not implemented\n");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_REQ_TYPE_NOTSUPP));

		break;

	case MANAGEMENT_ORB_FUNCTION_LOGOUT:
		sbp_management_request_logout(agent, req, &status_data_len);
		break;

	case MANAGEMENT_ORB_FUNCTION_ABORT_TASK:
		pr_notice("ABORT TASK not implemented\n");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_REQ_TYPE_NOTSUPP));

		break;

	case MANAGEMENT_ORB_FUNCTION_ABORT_TASK_SET:
		pr_notice("ABORT TASK SET not implemented\n");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_REQ_TYPE_NOTSUPP));

		break;

	case MANAGEMENT_ORB_FUNCTION_LOGICAL_UNIT_RESET:
		pr_notice("LOGICAL UNIT RESET not implemented\n");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_REQ_TYPE_NOTSUPP));

		break;

	case MANAGEMENT_ORB_FUNCTION_TARGET_RESET:
		pr_notice("TARGET RESET not implemented\n");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_REQ_TYPE_NOTSUPP));

		break;

	default:
		pr_notice("unknown management function 0x%x\n",
			MANAGEMENT_ORB_FUNCTION(be32_to_cpu(req->orb.misc)));

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_REQ_TYPE_NOTSUPP));

		break;
	}

	req->status.status |= cpu_to_be32(
		STATUS_BLOCK_SRC(1) | /* Response to ORB, next_ORB absent */
		STATUS_BLOCK_LEN(DIV_ROUND_UP(status_data_len, 4) + 1) |
		STATUS_BLOCK_ORB_OFFSET_HIGH(agent->orb_offset >> 32));
	req->status.orb_low = cpu_to_be32(agent->orb_offset);

	/* write the status block back to the initiator */
	ret = sbp_run_transaction(req->card, TCODE_WRITE_BLOCK_REQUEST,
		req->node_addr, req->generation, req->speed,
		sbp2_pointer_to_addr(&req->orb.status_fifo),
		&req->status, 8 + status_data_len);
	if (ret != RCODE_COMPLETE) {
		pr_debug("mgt_orb status write failed: %x\n", ret);
		goto out;
	}

out:
	fw_card_put(req->card);
	kfree(req);

	spin_lock_bh(&agent->lock);
	agent->state = MANAGEMENT_AGENT_STATE_IDLE;
	spin_unlock_bh(&agent->lock);
}

static void sbp_mgt_agent_rw(struct fw_card *card,
	struct fw_request *request, int tcode, int destination, int source,
	int generation, unsigned long long offset, void *data, size_t length,
	void *callback_data)
{
	struct sbp_management_agent *agent = callback_data;
	struct sbp2_pointer *ptr = data;
	int rcode = RCODE_ADDRESS_ERROR;

	if (!agent->tport->enable)
		goto out;

	if ((offset != agent->handler.offset) || (length != 8))
		goto out;

	if (tcode == TCODE_WRITE_BLOCK_REQUEST) {
		struct sbp_management_request *req;
		int prev_state;

		spin_lock_bh(&agent->lock);
		prev_state = agent->state;
		agent->state = MANAGEMENT_AGENT_STATE_BUSY;
		spin_unlock_bh(&agent->lock);

		if (prev_state == MANAGEMENT_AGENT_STATE_BUSY) {
			pr_notice("ignoring management request while busy\n");
			rcode = RCODE_CONFLICT_ERROR;
			goto out;
		}

		req = kzalloc(sizeof(*req), GFP_ATOMIC);
		if (!req) {
			rcode = RCODE_CONFLICT_ERROR;
			goto out;
		}

		req->card = fw_card_get(card);
		req->generation = generation;
		req->node_addr = source;
		req->speed = fw_get_request_speed(request);

		agent->orb_offset = sbp2_pointer_to_addr(ptr);
		agent->request = req;

		queue_work(system_unbound_wq, &agent->work);
		rcode = RCODE_COMPLETE;
	} else if (tcode == TCODE_READ_BLOCK_REQUEST) {
		addr_to_sbp2_pointer(agent->orb_offset, ptr);
		rcode = RCODE_COMPLETE;
	} else {
		rcode = RCODE_TYPE_ERROR;
	}

out:
	fw_send_response(card, request, rcode);
}

struct sbp_management_agent *sbp_management_agent_register(
		struct sbp_tport *tport)
{
	int ret;
	struct sbp_management_agent *agent;

	agent = kmalloc(sizeof(*agent), GFP_KERNEL);
	if (!agent)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&agent->lock);
	agent->tport = tport;
	agent->handler.length = 0x08;
	agent->handler.address_callback = sbp_mgt_agent_rw;
	agent->handler.callback_data = agent;
	agent->state = MANAGEMENT_AGENT_STATE_IDLE;
	INIT_WORK(&agent->work, sbp_mgt_agent_process);
	agent->orb_offset = 0;
	agent->request = NULL;

	ret = fw_core_add_address_handler(&agent->handler,
			&sbp_register_region);
	if (ret < 0) {
		kfree(agent);
		return ERR_PTR(ret);
	}

	return agent;
}

void sbp_management_agent_unregister(struct sbp_management_agent *agent)
{
	fw_core_remove_address_handler(&agent->handler);
	cancel_work_sync(&agent->work);
	kfree(agent);
}
