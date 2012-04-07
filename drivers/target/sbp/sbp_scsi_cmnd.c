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

struct sbp_rw_data_txn {
	int max_payload;
	int pg_size;

	struct fw_card *card;
	int node_id;
	int generation;
	int tcode;
	int speed;

	struct sbp_page_table_entry *pg_tbl;
	int num_pte;

	unsigned long long offset;
	void *payload;
	int length;
};

/*
 * Simple wrapper around fw_run_transaction that retries the transaction several
 * times in case of failure, with an exponential backoff.
 */
int sbp_run_transaction(struct fw_card *card, int tcode, int destination_id,
		int generation, int speed, unsigned long long offset,
		void *payload, size_t length)
{
	int attempt, ret, delay;

	for (attempt = 1; attempt <= 5; attempt++) {
		ret = fw_run_transaction(card, tcode, destination_id,
				generation, speed, offset, payload, length);

		switch (ret) {
		case RCODE_COMPLETE:
		case RCODE_TYPE_ERROR:
		case RCODE_ADDRESS_ERROR:
		case RCODE_GENERATION:
			return ret;

		default:
			delay = 5 * attempt * attempt;
			usleep_range(delay, delay * 2);
		}
	}

	return ret;
}

/*
 * Wrapper around sbp_run_transaction that gets the card, destination,
 * generation and speed out of the request's session.
 */
static int sbp_run_request_transaction(struct sbp_target_request *req,
		int tcode, unsigned long long offset, void *payload,
		size_t length)
{
	struct sbp_login_descriptor *login = req->login;
	struct sbp_session *sess = login->sess;
	struct fw_card *card;
	int node_id, generation, speed, ret;

	spin_lock_bh(&sess->lock);
	card = fw_card_get(sess->card);
	node_id = sess->node_id;
	generation = sess->generation;
	speed = sess->speed;
	spin_unlock_bh(&sess->lock);

	ret = sbp_run_transaction(card, tcode, node_id, generation, speed,
			offset, payload, length);

	fw_card_put(card);

	return ret;
}

static int sbp_fetch_command(struct sbp_target_request *req)
{
	int ret, cmd_len, copy_len;

	cmd_len = scsi_command_size(req->orb.command_block);

	req->cmd_buf = kmalloc(cmd_len, GFP_KERNEL);
	if (!req->cmd_buf)
		return -ENOMEM;

	memcpy(req->cmd_buf, req->orb.command_block,
		min_t(int, cmd_len, sizeof(req->orb.command_block)));

	if (cmd_len > sizeof(req->orb.command_block)) {
		pr_debug("sbp_fetch_command: filling in long command\n");
		copy_len = cmd_len - sizeof(req->orb.command_block);

		ret = sbp_run_request_transaction(req,
				TCODE_READ_BLOCK_REQUEST,
				req->orb_pointer + sizeof(req->orb),
				req->cmd_buf + sizeof(req->orb.command_block),
				copy_len);
		if (ret != RCODE_COMPLETE)
			return -EIO;
	}

	return 0;
}

static int sbp_fetch_page_table(struct sbp_target_request *req)
{
	int pg_tbl_sz, ret;
	struct sbp_page_table_entry *pg_tbl;

	if (!CMDBLK_ORB_PG_TBL_PRESENT(be32_to_cpu(req->orb.misc)))
		return 0;

	pg_tbl_sz = CMDBLK_ORB_DATA_SIZE(be32_to_cpu(req->orb.misc)) *
		sizeof(struct sbp_page_table_entry);

	pg_tbl = kmalloc(pg_tbl_sz, GFP_KERNEL);
	if (!pg_tbl)
		return -ENOMEM;

	ret = sbp_run_request_transaction(req, TCODE_READ_BLOCK_REQUEST,
			sbp2_pointer_to_addr(&req->orb.data_descriptor),
			pg_tbl, pg_tbl_sz);
	if (ret != RCODE_COMPLETE) {
		kfree(pg_tbl);
		return -EIO;
	}

	req->pg_tbl = pg_tbl;
	return 0;
}

static void sbp_calc_data_length_direction(struct sbp_target_request *req,
	u32 *data_len, enum dma_data_direction *data_dir)
{
	int data_size, direction, idx;

	data_size = CMDBLK_ORB_DATA_SIZE(be32_to_cpu(req->orb.misc));
	direction = CMDBLK_ORB_DIRECTION(be32_to_cpu(req->orb.misc));

	if (!data_size) {
		*data_len = 0;
		*data_dir = DMA_NONE;
		return;
	}

	*data_dir = direction ? DMA_FROM_DEVICE : DMA_TO_DEVICE;

	if (req->pg_tbl) {
		*data_len = 0;
		for (idx = 0; idx < data_size; idx++) {
			*data_len += be16_to_cpu(
					req->pg_tbl[idx].segment_length);
		}
	} else {
		*data_len = data_size;
	}
}

void sbp_handle_command(struct sbp_target_request *req)
{
	struct sbp_login_descriptor *login = req->login;
	struct sbp_session *sess = login->sess;
	int ret, unpacked_lun;
	u32 data_length;
	enum dma_data_direction data_dir;

	ret = sbp_fetch_command(req);
	if (ret) {
		pr_debug("sbp_handle_command: fetch command failed: %d\n", ret);
		req->status.status |= cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_TRANSPORT_FAILURE) |
			STATUS_BLOCK_DEAD(0) |
			STATUS_BLOCK_LEN(1) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_UNSPECIFIED_ERROR));
		sbp_send_status(req);
		sbp_free_request(req);
		return;
	}

	ret = sbp_fetch_page_table(req);
	if (ret) {
		pr_debug("sbp_handle_command: fetch page table failed: %d\n",
			ret);
		req->status.status |= cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_TRANSPORT_FAILURE) |
			STATUS_BLOCK_DEAD(0) |
			STATUS_BLOCK_LEN(1) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_UNSPECIFIED_ERROR));
		sbp_send_status(req);
		sbp_free_request(req);
		return;
	}

	unpacked_lun = req->login->lun->unpacked_lun;
	sbp_calc_data_length_direction(req, &data_length, &data_dir);

	pr_debug("sbp_handle_command unpacked_lun:%d data_len:%d data_dir:%d\n",
			unpacked_lun, data_length, data_dir);

	target_submit_cmd(&req->se_cmd, sess->se_sess, req->cmd_buf,
			req->sense_buf, unpacked_lun, data_length,
			MSG_SIMPLE_TAG, data_dir, 0);
}

/* txn->mutex must already be held */
static inline bool sbp_rw_data_continue(struct sbp_rw_data_txn *txn)
{
	struct sbp_page_table_entry *pte;

	if (txn->length)
		return true;

	if (!txn->num_pte)
		return false;

	pte = txn->pg_tbl;
	txn->offset = (u64)be16_to_cpu(pte->segment_base_hi) << 32 |
		be32_to_cpu(pte->segment_base_lo);
	txn->length = be16_to_cpu(pte->segment_length);

	txn->pg_tbl++;
	txn->num_pte--;

	return true;
}

static int sbp_rw_data_worker(struct sbp_rw_data_txn *txn)
{
	unsigned long long offset;
	void *payload;
	int length, attempt, delay, rcode = RCODE_COMPLETE;

	while (sbp_rw_data_continue(txn)) {
		offset = txn->offset;
		payload = txn->payload;
		length = txn->length;

		if (length > txn->max_payload)
			length = txn->max_payload;

		/* FIXME: take page_size into account */

		txn->length -= length;
		txn->offset += length;
		txn->payload += length;

		pr_debug("worker txn: 0x%p to 0x%08llx len 0x%x\n",
			payload, offset, length);

		for (attempt = 1; attempt <= 5; attempt++) {
			rcode = fw_run_transaction(txn->card,
					txn->tcode, txn->node_id,
					txn->generation, txn->speed,
					offset, payload, length);

			if (rcode == RCODE_COMPLETE)
				break;

			delay = 5 * attempt * attempt;
			usleep_range(delay, delay * 2);
		}

		if (rcode != RCODE_COMPLETE)
			break;
	}

	return rcode;
}

/*
 * DMA_TO_DEVICE = read from initiator (SCSI WRITE)
 * DMA_FROM_DEVICE = write to initiator (SCSI READ)
 */
int sbp_rw_data(struct sbp_target_request *req)
{
	struct sbp_session *sess = req->login->sess;
	int tcode, rcode, ret = 0;
	struct sbp_rw_data_txn *txn;
	void *data_buf;

	data_buf = kmalloc(req->se_cmd.data_length, GFP_KERNEL);
	if (!data_buf)
		return -ENOMEM;

	if (req->se_cmd.data_direction == DMA_FROM_DEVICE) {
		sg_copy_to_buffer(req->se_cmd.t_data_sg,
				req->se_cmd.t_data_nents,
				data_buf,
				req->se_cmd.data_length);
	}

	tcode = (req->se_cmd.data_direction == DMA_TO_DEVICE) ?
		TCODE_READ_BLOCK_REQUEST :
		TCODE_WRITE_BLOCK_REQUEST;

	txn = kmalloc(sizeof(*txn), GFP_KERNEL);
	if (!txn)
		return -ENOMEM;

	txn->max_payload = 4 << CMDBLK_ORB_MAX_PAYLOAD(
			be32_to_cpu(req->orb.misc));

	txn->pg_size = CMDBLK_ORB_PG_SIZE(be32_to_cpu(req->orb.misc));
	if (txn->pg_size) {
		pr_err("sbp_run_transaction: page size ignored\n");
		txn->pg_size = 0x100 << txn->pg_size;
	}

	spin_lock_bh(&sess->lock);
	txn->card = fw_card_get(sess->card);
	txn->node_id = sess->node_id;
	txn->generation = sess->generation;
	spin_unlock_bh(&sess->lock);

	txn->tcode = tcode;
	txn->speed = CMDBLK_ORB_SPEED(be32_to_cpu(req->orb.misc));

	if (req->pg_tbl) {
		txn->pg_tbl = req->pg_tbl;
		txn->num_pte = CMDBLK_ORB_DATA_SIZE(be32_to_cpu(req->orb.misc));

		txn->offset = 0;
		txn->length = 0;
	} else {
		txn->pg_tbl = NULL;
		txn->num_pte = 0;

		txn->offset = sbp2_pointer_to_addr(&req->orb.data_descriptor);
		txn->length = req->se_cmd.data_length;
	}

	txn->payload = data_buf;

	rcode = sbp_rw_data_worker(txn);

	if (rcode != RCODE_COMPLETE) {
		ret = -EIO;
	} else if (req->se_cmd.data_direction == DMA_TO_DEVICE) {
		sg_copy_from_buffer(req->se_cmd.t_data_sg,
				req->se_cmd.t_data_nents,
				data_buf,
				req->se_cmd.data_length);
	}

	WARN_ON(ret == 0 && txn->length != 0);

	fw_card_put(txn->card);
	kfree(data_buf);
	kfree(txn);

	return ret;
}

int sbp_send_status(struct sbp_target_request *req)
{
	int ret, length;
	struct sbp_login_descriptor *login = req->login;

	length = (((be32_to_cpu(req->status.status) >> 24) & 0x07) + 1) * 4;

	ret = sbp_run_request_transaction(req, TCODE_WRITE_BLOCK_REQUEST,
			login->status_fifo_addr, &req->status, length);
	if (ret != RCODE_COMPLETE) {
		pr_debug("sbp_send_status: write failed: 0x%x\n", ret);
		return -EIO;
	}

	pr_debug("sbp_send_status: status write complete for ORB: 0x%llx\n",
			req->orb_pointer);

	return 0;
}

static void sbp_sense_mangle(struct sbp_target_request *req)
{
	struct se_cmd *se_cmd = &req->se_cmd;
	u8 *sense = req->sense_buf;
	u8 *status = req->status.data;

	WARN_ON(se_cmd->scsi_sense_length < 18);

	switch (sense[0] & 0x7f) { 		/* sfmt */
	case 0x70: /* current, fixed */
		status[0] = 0 << 6;
		break;
	case 0x71: /* deferred, fixed */
		status[0] = 1 << 6;
		break;
	case 0x72: /* current, descriptor */
	case 0x73: /* deferred, descriptor */
	default:
		/*
		 * TODO: SBP-3 specifies what we should do with descriptor
		 * format sense data
		 */
		pr_err("sbp_send_sense: unknown sense format: 0x%x\n",
			sense[0]);
		req->status.status |= cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_DEAD(0) |
			STATUS_BLOCK_LEN(1) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_REQUEST_ABORTED));
		return;
	}

	status[0] |= se_cmd->scsi_status & 0x3f;/* status */
	status[1] =
		(sense[0] & 0x80) |		/* valid */
		((sense[2] & 0xe0) >> 1) |	/* mark, eom, ili */
		(sense[2] & 0x0f);		/* sense_key */
	status[2] = se_cmd->scsi_asc;		/* sense_code */
	status[3] = se_cmd->scsi_ascq;		/* sense_qualifier */

	/* information */
	status[4] = sense[3];
	status[5] = sense[4];
	status[6] = sense[5];
	status[7] = sense[6];

	/* CDB-dependent */
	status[8] = sense[8];
	status[9] = sense[9];
	status[10] = sense[10];
	status[11] = sense[11];

	/* fru */
	status[12] = sense[14];

	/* sense_key-dependent */
	status[13] = sense[15];
	status[14] = sense[16];
	status[15] = sense[17];

	req->status.status |= cpu_to_be32(
		STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
		STATUS_BLOCK_DEAD(0) |
		STATUS_BLOCK_LEN(5) |
		STATUS_BLOCK_SBP_STATUS(SBP_STATUS_OK));
}

int sbp_send_sense(struct sbp_target_request *req)
{
	struct se_cmd *se_cmd = &req->se_cmd;

	if (se_cmd->scsi_sense_length) {
		sbp_sense_mangle(req);
	} else {
		req->status.status |= cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_DEAD(0) |
			STATUS_BLOCK_LEN(1) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_OK));
	}

	return sbp_send_status(req);
}

void sbp_free_request(struct sbp_target_request *req)
{
	kfree(req->pg_tbl);
	kfree(req->cmd_buf);
	kfree(req);
}
