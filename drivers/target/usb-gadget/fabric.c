 /*
  * Target based USB-Gadget, target callbacks
  * Transport protocol handling.
  * Author: Sebastian Andrzej Siewior <bigeasy at linutronix dot de>
  * License: GPLv2 as published by FSF.
  */

#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/usb/storage.h>
#include <asm/unaligned.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/libfc.h>
#include <scsi/scsi_tcq.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_configfs.h>

#include "usbg.h"

static int get_cmd_dir(const unsigned char *cdb)
{
	int ret;

	switch (cdb[0]) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	case INQUIRY:
	case MODE_SENSE:
	case MODE_SENSE_10:
	case SERVICE_ACTION_IN:
	case MAINTENANCE_IN:
	case PERSISTENT_RESERVE_IN:
	case SECURITY_PROTOCOL_IN:
	case ACCESS_CONTROL_IN:
	case REPORT_LUNS:
	case READ_BLOCK_LIMITS:
	case READ_POSITION:
	case READ_CAPACITY:
	case READ_TOC:
	case READ_FORMAT_CAPACITIES:
	case REQUEST_SENSE:
		ret = DMA_FROM_DEVICE;
		break;

	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case MODE_SELECT:
	case MODE_SELECT_10:
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case PERSISTENT_RESERVE_OUT:
	case MAINTENANCE_OUT:
	case SECURITY_PROTOCOL_OUT:
	case ACCESS_CONTROL_OUT:
		ret = DMA_TO_DEVICE;
		break;
	case ALLOW_MEDIUM_REMOVAL:
	case TEST_UNIT_READY:
	case SYNCHRONIZE_CACHE:
	case START_STOP:
	case ERASE:
	case REZERO_UNIT:
	case SEEK_10:
	case SPACE:
	case VERIFY:
	case WRITE_FILEMARKS:
		ret = DMA_NONE;
		break;
	default:
		pr_warn("target: Unknown data direction for SCSI Opcode "
				"0x%02x\n", cdb[0]);
		ret = -EINVAL;
	}
	return ret;
}

void usbg_data_write_cmpl(struct usb_ep *ep, struct usb_request *req)
{
	struct usbg_cmd *cmd = req->context;
	struct se_cmd *se_cmd = &cmd->se_cmd;

	if (req->status < 0) {
		pr_err("%s() state %d transfer failed\n", __func__, cmd->state);
		goto cleanup;
	}

	if (req->num_sgs == 0) {
		sg_copy_from_buffer(se_cmd->t_data_sg,
				se_cmd->t_data_nents,
				cmd->data_buf,
				se_cmd->data_length);
	}

	complete(&cmd->write_complete);
	return;

cleanup:
	usbg_cleanup_cmd(cmd);
}

int usbg_prepare_w_request(struct usbg_cmd *cmd, struct usb_request *req)
{
	struct se_cmd *se_cmd = &cmd->se_cmd;
	struct f_uas *fu = cmd->fu;
	struct usb_gadget *gadget = fuas_to_gadget(fu);

	if (!gadget->sg_supported) {
		cmd->data_buf = kmalloc(se_cmd->data_length, GFP_ATOMIC);
		if (!cmd->data_buf)
			return -ENOMEM;

		req->buf = cmd->data_buf;
	} else {
		req->buf = NULL;
		req->num_sgs = se_cmd->t_data_nents;
		req->sg = se_cmd->t_data_sg;
	}

	req->complete = usbg_data_write_cmpl;
	req->length = se_cmd->data_length;
	req->context = cmd;
	return 0;
}

int usbg_send_status_response(struct se_cmd *se_cmd)
{
	struct usbg_cmd *cmd = container_of(se_cmd, struct usbg_cmd,
			se_cmd);
	struct f_uas *fu = cmd->fu;

	if (fu->flags & USBG_IS_BOT)
		return bot_send_status_response(cmd);
	else
		return uasp_send_status_response(cmd);
}

int usbg_send_write_request(struct se_cmd *se_cmd)
{
	struct usbg_cmd *cmd = container_of(se_cmd, struct usbg_cmd,
			se_cmd);
	struct f_uas *fu = cmd->fu;

	if (fu->flags & USBG_IS_BOT)
		return bot_send_write_request(cmd);
	else
		return uasp_send_write_request(cmd);
}

int usbg_send_read_response(struct se_cmd *se_cmd)
{
	struct usbg_cmd *cmd = container_of(se_cmd, struct usbg_cmd,
			se_cmd);
	struct f_uas *fu = cmd->fu;

	if (fu->flags & USBG_IS_BOT)
		return bot_send_read_response(cmd);
	else
		return uasp_send_read_response(cmd);
}

static void usbg_cmd_work(struct work_struct *work)
{
	struct usbg_cmd *cmd = container_of(work, struct usbg_cmd, work);
	struct se_cmd *se_cmd;
	struct tcm_usbg_nexus *tv_nexus;
	struct usbg_tpg *tpg;
	int dir;

	se_cmd = &cmd->se_cmd;
	tpg = cmd->fu->tpg;
	tv_nexus = tpg->tpg_nexus;
	dir = get_cmd_dir(cmd->cmd_buf);
	if (dir < 0) {
		transport_init_se_cmd(se_cmd,
				tv_nexus->tvn_se_sess->se_tpg->se_tpg_tfo,
				tv_nexus->tvn_se_sess, cmd->data_len, DMA_NONE,
				cmd->prio_attr, cmd->sense_iu.sense);

		transport_send_check_condition_and_sense(se_cmd,
				TCM_UNSUPPORTED_SCSI_OPCODE, 1);
		usbg_cleanup_cmd(cmd);
		return;
	}

	target_submit_cmd(se_cmd, tv_nexus->tvn_se_sess,
			cmd->cmd_buf, cmd->sense_iu.sense, cmd->unpacked_lun,
			0, cmd->prio_attr, dir, TARGET_SCF_UNKNOWN_SIZE);
}

int usbg_submit_command(struct f_uas *fu,
		void *cmdbuf, unsigned int len)
{
	struct command_iu *cmd_iu = cmdbuf;
	struct usbg_cmd *cmd;
	struct usbg_tpg *tpg;
	struct se_cmd *se_cmd;
	struct tcm_usbg_nexus *tv_nexus;
	u32 cmd_len;
	int ret;

	if (cmd_iu->iu_id != IU_ID_COMMAND) {
		pr_err("Unsupported type %d\n", cmd_iu->iu_id);
		return -EINVAL;
	}

	cmd = kzalloc(sizeof *cmd, GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	cmd->fu = fu;

	/* XXX until I figure out why I can't free in on complete */
	kref_init(&cmd->ref);
	kref_get(&cmd->ref);

	tpg = fu->tpg;
	cmd_len = (cmd_iu->len & ~0x3) + 16;
	if (cmd_len > USBG_MAX_CMD)
		goto err;

	memcpy(cmd->cmd_buf, cmd_iu->cdb, cmd_len);

	cmd->tag = be16_to_cpup(&cmd_iu->tag);
	if (fu->flags & USBG_USE_STREAMS) {
		if (cmd->tag > UASP_SS_EP_COMP_NUM_STREAMS)
			goto err;
		if (!cmd->tag)
			cmd->stream = &fu->stream[0];
		else
			cmd->stream = &fu->stream[cmd->tag - 1];
	} else {
		cmd->stream = &fu->stream[0];
	}

	tv_nexus = tpg->tpg_nexus;
	if (!tv_nexus) {
		pr_err("Missing nexus, ignoring command\n");
		goto err;
	}

	switch (cmd_iu->prio_attr & 0x7) {
	case UAS_HEAD_TAG:
		cmd->prio_attr = MSG_HEAD_TAG;
		break;
	case UAS_ORDERED_TAG:
		cmd->prio_attr = MSG_ORDERED_TAG;
		break;
	case UAS_ACA:
		cmd->prio_attr = MSG_ACA_TAG;
		break;
	default:
		pr_debug_once("Unsupported prio_attr: %02x.\n",
				cmd_iu->prio_attr);
	case UAS_SIMPLE_TAG:
		cmd->prio_attr = MSG_SIMPLE_TAG;
		break;
	}

	se_cmd = &cmd->se_cmd;
	cmd->unpacked_lun = scsilun_to_int(&cmd_iu->lun);

	INIT_WORK(&cmd->work, usbg_cmd_work);
	ret = queue_work(tpg->workqueue, &cmd->work);
	if (ret < 0)
		goto err;

	return 0;
err:
	kfree(cmd);
	return -EINVAL;
}

static void bot_cmd_work(struct work_struct *work)
{
	struct usbg_cmd *cmd = container_of(work, struct usbg_cmd, work);
	struct se_cmd *se_cmd;
	struct tcm_usbg_nexus *tv_nexus;
	struct usbg_tpg *tpg;
	int dir;

	se_cmd = &cmd->se_cmd;
	tpg = cmd->fu->tpg;
	tv_nexus = tpg->tpg_nexus;
	dir = get_cmd_dir(cmd->cmd_buf);
	if (dir < 0) {
		transport_init_se_cmd(se_cmd,
				tv_nexus->tvn_se_sess->se_tpg->se_tpg_tfo,
				tv_nexus->tvn_se_sess, cmd->data_len, DMA_NONE,
				cmd->prio_attr, cmd->sense_iu.sense);

		transport_send_check_condition_and_sense(se_cmd,
				TCM_UNSUPPORTED_SCSI_OPCODE, 1);
		usbg_cleanup_cmd(cmd);
		return;
	}

	target_submit_cmd(se_cmd, tv_nexus->tvn_se_sess,
			cmd->cmd_buf, cmd->sense_iu.sense, cmd->unpacked_lun,
			cmd->data_len, cmd->prio_attr, dir, 0);
}

int bot_submit_command(struct f_uas *fu,
		void *cmdbuf, unsigned int len)
{
	struct bulk_cb_wrap *cbw = cmdbuf;
	struct usbg_cmd *cmd;
	struct usbg_tpg *tpg;
	struct se_cmd *se_cmd;
	struct tcm_usbg_nexus *tv_nexus;
	u32 cmd_len;
	int ret;

	if (cbw->Signature != cpu_to_le32(US_BULK_CB_SIGN)) {
		pr_err("Wrong signature on CBW\n");
		return -EINVAL;
	}
	if (len != 31) {
		pr_err("Wrong length for CBW\n");
		return -EINVAL;
	}

	cmd_len = cbw->Length;
	if (cmd_len < 1 || cmd_len > 16)
		return -EINVAL;

	cmd = kzalloc(sizeof *cmd, GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	cmd->fu = fu;

	/* XXX until I figure out why I can't free in on complete */
	kref_init(&cmd->ref);
	kref_get(&cmd->ref);

	tpg = fu->tpg;

	memcpy(cmd->cmd_buf, cbw->CDB, cmd_len);

	cmd->bot_tag = cbw->Tag;

	tv_nexus = tpg->tpg_nexus;
	if (!tv_nexus) {
		pr_err("Missing nexus, ignoring command\n");
		goto err;
	}

	cmd->prio_attr = MSG_SIMPLE_TAG;
	se_cmd = &cmd->se_cmd;
	cmd->unpacked_lun = cbw->Lun;
	cmd->is_read = cbw->Flags & US_BULK_FLAG_IN ? 1 : 0;
	cmd->data_len = le32_to_cpu(cbw->DataTransferLength);

	INIT_WORK(&cmd->work, bot_cmd_work);
	ret = queue_work(tpg->workqueue, &cmd->work);
	if (ret < 0)
		goto err;

	return 0;
err:
	kfree(cmd);
	return -EINVAL;
}

int usbg_check_true(struct se_portal_group *se_tpg)
{
	return 1;
}

int usbg_check_false(struct se_portal_group *se_tpg)
{
	return 0;
}

char *usbg_get_fabric_name(void)
{
	return "usb_gadget";
}

u8 usbg_get_fabric_proto_ident(struct se_portal_group *se_tpg)
{
	struct usbg_tpg *tpg = container_of(se_tpg,
				struct usbg_tpg, se_tpg);
	struct usbg_tport *tport = tpg->tport;
	u8 proto_id;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
	default:
		proto_id = sas_get_fabric_proto_ident(se_tpg);
		break;
	}

	return proto_id;
}

char *usbg_get_fabric_wwn(struct se_portal_group *se_tpg)
{
	struct usbg_tpg *tpg = container_of(se_tpg,
				struct usbg_tpg, se_tpg);
	struct usbg_tport *tport = tpg->tport;

	return &tport->tport_name[0];
}

u16 usbg_get_tag(struct se_portal_group *se_tpg)
{
	struct usbg_tpg *tpg = container_of(se_tpg,
				struct usbg_tpg, se_tpg);
	return tpg->tport_tpgt;
}

u32 usbg_get_default_depth(struct se_portal_group *se_tpg)
{
	return 1;
}

u32 usbg_get_pr_transport_id(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct t10_pr_registration *pr_reg,
	int *format_code,
	unsigned char *buf)
{
	struct usbg_tpg *tpg = container_of(se_tpg,
				struct usbg_tpg, se_tpg);
	struct usbg_tport *tport = tpg->tport;
	int ret = 0;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
	default:
		ret = sas_get_pr_transport_id(se_tpg, se_nacl, pr_reg,
					format_code, buf);
		break;
	}

	return ret;
}

u32 usbg_get_pr_transport_id_len(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct t10_pr_registration *pr_reg,
	int *format_code)
{
	struct usbg_tpg *tpg = container_of(se_tpg,
				struct usbg_tpg, se_tpg);
	struct usbg_tport *tport = tpg->tport;
	int ret = 0;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
	default:
		ret = sas_get_pr_transport_id_len(se_tpg, se_nacl, pr_reg,
					format_code);
		break;
	}

	return ret;
}

char *usbg_parse_pr_out_transport_id(
	struct se_portal_group *se_tpg,
	const char *buf,
	u32 *out_tid_len,
	char **port_nexus_ptr)
{
	struct usbg_tpg *tpg = container_of(se_tpg,
				struct usbg_tpg, se_tpg);
	struct usbg_tport *tport = tpg->tport;
	char *tid = NULL;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
	default:
		tid = sas_parse_pr_out_transport_id(se_tpg, buf, out_tid_len,
					port_nexus_ptr);
	}

	return tid;
}

struct se_node_acl *usbg_alloc_fabric_acl(struct se_portal_group *se_tpg)
{
	struct usbg_nacl *nacl;

	nacl = kzalloc(sizeof(struct usbg_nacl), GFP_KERNEL);
	if (!nacl) {
		printk(KERN_ERR "Unable to alocate struct usbg_nacl\n");
		return NULL;
	}

	return &nacl->se_node_acl;
}

void usbg_release_fabric_acl(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl)
{
	struct usbg_nacl *nacl = container_of(se_nacl,
			struct usbg_nacl, se_node_acl);
	kfree(nacl);
}

u32 usbg_tpg_get_inst_index(struct se_portal_group *se_tpg)
{
	return 1;
}

int usbg_new_cmd(struct se_cmd *se_cmd)
{
	struct usbg_cmd *cmd = container_of(se_cmd, struct usbg_cmd,
			se_cmd);
	int ret;

	ret = target_setup_cmd_from_cdb(se_cmd, cmd->cmd_buf);
	if (ret)
		return ret;

	return transport_generic_map_mem_to_cmd(se_cmd, NULL, 0, NULL, 0);
}

void usbg_cmd_release(struct kref *ref)
{
	struct usbg_cmd *cmd = container_of(ref, struct usbg_cmd,
			ref);

	transport_generic_free_cmd(&cmd->se_cmd, 0);
}

void usbg_release_cmd(struct se_cmd *se_cmd)
{
	struct usbg_cmd *cmd = container_of(se_cmd, struct usbg_cmd,
			se_cmd);
	kfree(cmd->data_buf);
	kfree(cmd);
	return;
}

int usbg_shutdown_session(struct se_session *se_sess)
{
	return 0;
}

void usbg_close_session(struct se_session *se_sess)
{
	return;
}

void usbg_stop_session(struct se_session *se_sess, int sess_sleep,
		int conn_sleep)
{
	return;
}

u32 usbg_sess_get_index(struct se_session *se_sess)
{
	return 0;
}

/*
 * XXX Error recovery: return != 0 if we expect writes. Dunno when that could be
 */
int usbg_write_pending_status(struct se_cmd *se_cmd)
{
	return 0;
}

void usbg_set_default_node_attrs(struct se_node_acl *nacl)
{
	return;
}

u32 usbg_get_task_tag(struct se_cmd *se_cmd)
{
	struct usbg_cmd *cmd = container_of(se_cmd, struct usbg_cmd,
			se_cmd);
	struct f_uas *fu = cmd->fu;

	if (fu->flags & USBG_IS_BOT)
		return le32_to_cpu(cmd->bot_tag);
	else
		return cmd->tag;
}

int usbg_get_cmd_state(struct se_cmd *se_cmd)
{
	return 0;
}

int usbg_queue_tm_rsp(struct se_cmd *se_cmd)
{
	return 0;
}

u16 usbg_set_fabric_sense_len(struct se_cmd *se_cmd, u32 sense_length)
{
	return 0;
}

u16 usbg_get_fabric_sense_len(void)
{
	return 0;
}
