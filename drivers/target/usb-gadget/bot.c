/*
 * Target based USB-Gadget, BOT protocol handling
 * Author: Sebastian Andrzej Siewior <bigeasy at linutronix dot de>
 * License: GPLv2 as published by FSF.
 */
#include <linux/kernel.h>
#include <linux/usb/ch9.h>
#include <linux/usb/composite.h>
#include <linux/usb/gadget.h>
#include <linux/usb/storage.h>

#include <target/target_core_base.h>

#include "usbg.h"

static int bot_enqueue_cmd_cbw(struct f_uas *fu)
{
	int ret;

	if (fu->flags & USBG_BOT_CMD_PEND)
		return 0;

	ret = usb_ep_queue(fu->ep_out, fu->cmd.req, GFP_ATOMIC);
	if (!ret)
		fu->flags |= USBG_BOT_CMD_PEND;
	return ret;
}

static void bot_status_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct usbg_cmd *cmd = req->context;
	struct f_uas *fu = cmd->fu;

	usbg_cleanup_cmd(cmd);
	if (req->status < 0) {
		pr_err("ERR %s(%d)\n", __func__, __LINE__);
		return;
	}

	/* CSW completed, wait for next CBW */
	bot_enqueue_cmd_cbw(fu);
}

static void bot_enqueue_sense_code(struct f_uas *fu, struct usbg_cmd *cmd)
{
	struct bulk_cs_wrap *csw = &fu->bot_status.csw;
	int ret;
	u8 *sense;
	unsigned int csw_stat;

	csw_stat = cmd->csw_code;

	/*
	 * We can't send SENSE as a response. So we take ASC & ASCQ from our
	 * sense buffer and queue it and hope the host sends a REQUEST_SENSE
	 * command where it learns why we failed.
	 */
	sense = cmd->sense_iu.sense;

	csw->Tag = cmd->bot_tag;
	csw->Status = csw_stat;
	fu->bot_status.req->context = cmd;
	ret = usb_ep_queue(fu->ep_in, fu->bot_status.req, GFP_ATOMIC);
	if (ret)
		pr_err("%s(%d) ERR: %d\n", __func__, __LINE__, ret);
}

static void bot_err_compl(struct usb_ep *ep, struct usb_request *req)
{
	struct usbg_cmd *cmd = req->context;
	struct f_uas *fu = cmd->fu;

	if (req->status < 0)
		pr_err("ERR %s(%d)\n", __func__, __LINE__);

	if (cmd->data_len) {
		if (cmd->data_len > ep->maxpacket) {
			req->length = ep->maxpacket;
			cmd->data_len -= ep->maxpacket;
		} else {
			req->length = cmd->data_len;
			cmd->data_len = 0;
		}

		usb_ep_queue(ep, req, GFP_ATOMIC);
		return ;
	}
	bot_enqueue_sense_code(fu, cmd);
}

static void bot_send_bad_status(struct usbg_cmd *cmd)
{
	struct f_uas *fu = cmd->fu;
	struct bulk_cs_wrap *csw = &fu->bot_status.csw;
	struct usb_request *req;
	struct usb_ep *ep;

	csw->Residue = cpu_to_le32(cmd->data_len);

	if (cmd->data_len) {
		if (cmd->is_read) {
			ep = fu->ep_in;
			req = fu->bot_req_in;
		} else {
			ep = fu->ep_out;
			req = fu->bot_req_out;
		}

		if (cmd->data_len > fu->ep_in->maxpacket) {
			req->length = ep->maxpacket;
			cmd->data_len -= ep->maxpacket;
		} else {
			req->length = cmd->data_len;
			cmd->data_len = 0;
		}
		req->complete = bot_err_compl;
		req->context = cmd;
		req->buf = fu->cmd.buf;
		usb_ep_queue(ep, req, GFP_KERNEL);
	} else {
		bot_enqueue_sense_code(fu, cmd);
	}
}

static int bot_send_status(struct usbg_cmd *cmd, bool moved_data)
{
	struct f_uas *fu = cmd->fu;
	struct bulk_cs_wrap *csw = &fu->bot_status.csw;
	int ret;

	if (cmd->se_cmd.scsi_status == SAM_STAT_GOOD) {
		if (!moved_data && cmd->data_len) {
			/*
			 * the host wants to move data, we don't. Fill / empty
			 * the pipe and then send the csw with reside set.
			 */
			cmd->csw_code = US_BULK_STAT_OK;
			bot_send_bad_status(cmd);
			return 0;
		}

		csw->Tag = cmd->bot_tag;
		csw->Residue = cpu_to_le32(0);
		csw->Status = US_BULK_STAT_OK;
		fu->bot_status.req->context = cmd;

		ret = usb_ep_queue(fu->ep_in, fu->bot_status.req, GFP_KERNEL);
		if (ret)
			pr_err("%s(%d) ERR: %d\n", __func__, __LINE__, ret);
	} else {
		cmd->csw_code = US_BULK_STAT_FAIL;
		bot_send_bad_status(cmd);
	}
	return 0;
}

/*
 * Called after command (no data transfer) or after the write (to device)
 * operation is completed
 */
int bot_send_status_response(struct usbg_cmd *cmd)
{
	bool moved_data = false;

	if (!cmd->is_read)
		moved_data = true;
	return bot_send_status(cmd, moved_data);
}

/* Read request completed, now we have to send the CSW */
static void bot_read_compl(struct usb_ep *ep, struct usb_request *req)
{
	struct usbg_cmd *cmd = req->context;

	if (req->status < 0)
		pr_err("ERR %s(%d)\n", __func__, __LINE__);

	bot_send_status(cmd, true);
}

int bot_send_read_response(struct usbg_cmd *cmd)
{
	struct f_uas *fu = cmd->fu;
	struct se_cmd *se_cmd = &cmd->se_cmd;
	struct usb_gadget *gadget = fuas_to_gadget(fu);
	int ret;

	if (!cmd->data_len) {
		cmd->csw_code = US_BULK_STAT_PHASE;
		bot_send_bad_status(cmd);
		return 0;
	}

	if (!gadget->sg_supported) {
		cmd->data_buf = kmalloc(se_cmd->data_length, GFP_ATOMIC);
		if (!cmd->data_buf)
			return -ENOMEM;

		sg_copy_to_buffer(se_cmd->t_data_sg,
				se_cmd->t_data_nents,
				cmd->data_buf,
				se_cmd->data_length);

		fu->bot_req_in->buf = cmd->data_buf;
	} else {
		fu->bot_req_in->buf = NULL;
		fu->bot_req_in->num_sgs = se_cmd->t_data_nents;
		fu->bot_req_in->sg = se_cmd->t_data_sg;
	}

	fu->bot_req_in->complete = bot_read_compl;
	fu->bot_req_in->length = se_cmd->data_length;
	fu->bot_req_in->context = cmd;
	ret = usb_ep_queue(fu->ep_in, fu->bot_req_in, GFP_ATOMIC);
	if (ret)
		pr_err("%s(%d)\n", __func__, __LINE__);
	return 0;
}

int bot_send_write_request(struct usbg_cmd *cmd)
{
	struct f_uas *fu = cmd->fu;
	struct se_cmd *se_cmd = &cmd->se_cmd;
	struct usb_gadget *gadget = fuas_to_gadget(fu);
	int ret;

	init_completion(&cmd->write_complete);
	cmd->fu = fu;

	if (!cmd->data_len) {
		cmd->csw_code = US_BULK_STAT_PHASE;
		return -EINVAL;
	}

	if (!gadget->sg_supported) {
		cmd->data_buf = kmalloc(se_cmd->data_length, GFP_KERNEL);
		if (!cmd->data_buf)
			return -ENOMEM;

		fu->bot_req_out->buf = cmd->data_buf;
	} else {
		fu->bot_req_out->buf = NULL;
		fu->bot_req_out->num_sgs = se_cmd->t_data_nents;
		fu->bot_req_out->sg = se_cmd->t_data_sg;
	}

	fu->bot_req_out->complete = usbg_data_write_cmpl;
	fu->bot_req_out->length = se_cmd->data_length;
	fu->bot_req_out->context = cmd;

	ret = usbg_prepare_w_request(cmd, fu->bot_req_out);
	if (ret)
		goto cleanup;
	ret = usb_ep_queue(fu->ep_out, fu->bot_req_out, GFP_KERNEL);
	if (ret)
		pr_err("%s(%d)\n", __func__, __LINE__);

	wait_for_completion(&cmd->write_complete);
	transport_generic_process_write(se_cmd);
cleanup:
	return ret;
}

static void bot_cmd_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_uas *fu = req->context;
	int ret;

	fu->flags &= ~USBG_BOT_CMD_PEND;

	if (req->status < 0)
		return;

	ret = bot_submit_command(fu, req->buf, req->actual);
	if (ret)
		pr_err("%s(%d): %d\n", __func__, __LINE__, ret);
}

static int bot_prepare_reqs(struct f_uas *fu)
{
	int ret;

	fu->bot_req_in = usb_ep_alloc_request(fu->ep_in, GFP_KERNEL);
	if (!fu->bot_req_in)
		goto err;

	fu->bot_req_out = usb_ep_alloc_request(fu->ep_out, GFP_KERNEL);
	if (!fu->bot_req_out)
		goto err_out;

	fu->cmd.req = usb_ep_alloc_request(fu->ep_out, GFP_KERNEL);
	if (!fu->cmd.req)
		goto err_cmd;

	fu->bot_status.req = usb_ep_alloc_request(fu->ep_in, GFP_KERNEL);
	if (!fu->bot_status.req)
		goto err_sts;

	fu->bot_status.req->buf = &fu->bot_status.csw;
	fu->bot_status.req->length = US_BULK_CS_WRAP_LEN;
	fu->bot_status.req->complete = bot_status_complete;
	fu->bot_status.csw.Signature = cpu_to_le32(US_BULK_CS_SIGN);

	fu->cmd.buf = kmalloc(fu->ep_out->maxpacket, GFP_KERNEL);
	if (!fu->cmd.buf)
		goto err_buf;

	fu->cmd.req->complete = bot_cmd_complete;
	fu->cmd.req->buf = fu->cmd.buf;
	fu->cmd.req->length = fu->ep_out->maxpacket;
	fu->cmd.req->context = fu;

	ret = bot_enqueue_cmd_cbw(fu);
	if (ret)
		goto err_queue;
	return 0;
err_queue:
	kfree(fu->cmd.buf);
	fu->cmd.buf = NULL;
err_buf:
	usb_ep_free_request(fu->ep_in, fu->bot_status.req);
err_sts:
	usb_ep_free_request(fu->ep_out, fu->cmd.req);
	fu->cmd.req = NULL;
err_cmd:
	usb_ep_free_request(fu->ep_out, fu->bot_req_out);
	fu->bot_req_out = NULL;
err_out:
	usb_ep_free_request(fu->ep_in, fu->bot_req_in);
	fu->bot_req_in = NULL;
err:
	pr_err("BOT: endpoint setup failed\n");
	return -ENOMEM;
}

void bot_cleanup_old_alt(struct f_uas *fu)
{
	if (!(fu->flags & USBG_ENABLED))
		return;

	usb_ep_disable(fu->ep_in);
	usb_ep_disable(fu->ep_out);

	if (!fu->bot_req_in)
		return;

	usb_ep_free_request(fu->ep_in, fu->bot_req_in);
	usb_ep_free_request(fu->ep_out, fu->bot_req_out);
	usb_ep_free_request(fu->ep_out, fu->cmd.req);
	usb_ep_free_request(fu->ep_out, fu->bot_status.req);

	kfree(fu->cmd.buf);

	fu->bot_req_in = NULL;
	fu->bot_req_out = NULL;
	fu->cmd.req = NULL;
	fu->bot_status.req = NULL;
	fu->cmd.buf = NULL;
}

void bot_set_alt(struct f_uas *fu)
{
	struct usb_function *f = &fu->function;
	struct usb_gadget *gadget = f->config->cdev->gadget;
	int ret;

	fu->flags = USBG_IS_BOT;

	config_ep_by_speed(gadget, f, fu->ep_in);
	ret = usb_ep_enable(fu->ep_in);
	if (ret)
		goto err_b_in;

	config_ep_by_speed(gadget, f, fu->ep_out);
	ret = usb_ep_enable(fu->ep_out);
	if (ret)
		goto err_b_out;

	ret = bot_prepare_reqs(fu);
	if (ret)
		goto err_wq;
	fu->flags |= USBG_ENABLED;
	pr_info("Using the BOT protocol\n");
	return;
err_wq:
	usb_ep_disable(fu->ep_out);
err_b_out:
	usb_ep_disable(fu->ep_in);
err_b_in:
	fu->flags = USBG_IS_BOT;
}

int usbg_bot_setup(struct usb_function *f,
		const struct usb_ctrlrequest *ctrl)
{
	struct f_uas *fu = to_f_uas(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	u16 w_value = le16_to_cpu(ctrl->wValue);
	u16 w_length = le16_to_cpu(ctrl->wLength);
	int luns;
	u8 *ret_lun;

	switch (ctrl->bRequest) {
	case US_BULK_GET_MAX_LUN:
		if (ctrl->bRequestType != (USB_DIR_IN | USB_TYPE_CLASS |
					USB_RECIP_INTERFACE))
			return -ENOTSUPP;

		if (w_length < 1)
			return -EINVAL;
		if (w_value != 0)
			return -EINVAL;
		luns = atomic_read(&fu->tpg->tpg_port_count);
		if (!luns) {
			pr_err("No LUNs configured?\n");
			return -EINVAL;
		}
		/*
		 * If 4 LUNs are present we return 3 i.e. LUN 0..3 can be
		 * accessed. The upper limit is 0xf
		 */
		luns--;
		if (luns > 0xf) {
			pr_info_once("Limiting the number of luns to 16\n");
			luns = 0xf;
		}
		ret_lun = cdev->req->buf;
		*ret_lun = luns;
		cdev->req->length = 1;
		return usb_ep_queue(cdev->gadget->ep0, cdev->req, GFP_ATOMIC);
		break;

	case US_BULK_RESET_REQUEST:
		/* XXX maybe we should remove previous requests for IN + OUT */
		bot_enqueue_cmd_cbw(fu);
		return 0;
		break;
	};
	return -ENOTSUPP;
}
