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

#include <linux/kernel.h>
#include <linux/firewire.h>
#include <linux/firewire-constants.h>

#include <scsi/scsi.h>
#include <scsi/scsi_tcq.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_fabric_configfs.h>
#include <target/target_core_configfs.h>

#include "sbp_base.h"
#include "sbp_target_agent.h"
#include "sbp_scsi_cmnd.h"
#include "sbp_util.h"

static u32 sbp_calc_data_length(struct sbp_command_block_orb *orb)
{
	int data_size, pg_tbl_present;

	data_size = CMDBLK_ORB_DATA_SIZE(be32_to_cpu(orb->misc));
	pg_tbl_present = CMDBLK_ORB_PG_TBL_PRESENT(be32_to_cpu(orb->misc));

	if (!data_size)
		return 0;
	else if (!pg_tbl_present)
		return data_size;
	else {
		/* FIXME: handle page tables... */
		pr_err("sbp_calc_data_length PAGETABLE!\n");
		return 0;
	}
}

static enum dma_data_direction sbp_data_direction(
		struct sbp_command_block_orb *orb)
{
	if (sbp_calc_data_length(orb) == 0)
		return DMA_NONE;

	if (CMDBLK_ORB_DIRECTION(be32_to_cpu(orb->misc)))
		return DMA_FROM_DEVICE;
	else
		return DMA_TO_DEVICE;
}

void sbp_handle_command(struct sbp_target_request *req)
{
	struct sbp_login_descriptor *login = req->agent->login;
	struct sbp_session *sess = login->sess;
	int cmd_len;

	cmd_len = scsi_command_size(req->orb.command_block);
	if (cmd_len <= sizeof(req->orb.command_block))
		req->cmd_buf = req->orb.command_block;
	else {
		/* FIXME: transfer remaining bytes of command */
		kfree(req);
		return;
	}

	req->unpacked_lun = req->agent->login->lun->unpacked_lun;
	req->data_len = sbp_calc_data_length(&req->orb);
	req->data_dir = sbp_data_direction(&req->orb);

	pr_notice("smb_handle_command cmd_len:%d unpacked_lun:%d data_len:%d "
			"data_dir:%d\n", cmd_len, req->unpacked_lun, req->data_len,
			req->data_dir);

	target_submit_cmd(&req->se_cmd, sess->se_sess, req->cmd_buf,
			req->sense_buf, req->unpacked_lun, 0, MSG_SIMPLE_TAG,
			req->data_dir, TARGET_SCF_UNKNOWN_SIZE);
}

/*
 * DMA_TO_DEVICE = read from initiator (SCSI WRITE)
 * DMA_FROM_DEVICE = write to initiator (SCSI READ)
 */
int sbp_rw_data(struct sbp_target_request *req)
{
	int pg_tbl_present, ret;
	struct sbp_login_descriptor *login = req->agent->login;
	struct sbp_session *sess = login->sess;

	WARN_ON(!req->data_len);

	pg_tbl_present = CMDBLK_ORB_PG_TBL_PRESENT(be32_to_cpu(req->orb.misc));
	if (pg_tbl_present) {
		pr_err("sbp_rw_data: page tables unimplemented\n");
		return -EIO;
	} else {
		ret = fw_run_transaction(sess->card, (req->data_dir == DMA_TO_DEVICE) ?
				TCODE_READ_BLOCK_REQUEST : TCODE_WRITE_BLOCK_REQUEST,
				sess->node_id, sess->generation, sess->speed,
				sbp2_pointer_to_addr(&req->orb.data_descriptor),
				req->data_buf, req->data_len);
		if (ret != RCODE_COMPLETE) {
			pr_err("sbp_rw_data: r/w failed: %x\n", ret);
			return -EIO;
		}
	}

	return 0;
}

