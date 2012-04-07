/*
 * Target based USB-Gadget, UAS protocol handling
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

static void uasp_cleanup_one_stream(struct f_uas *fu, struct uas_stream *stream)
{
	/* We have either all three allocated or none */
	if (!stream->req_in)
		return;

	usb_ep_free_request(fu->ep_in, stream->req_in);
	usb_ep_free_request(fu->ep_out, stream->req_out);
	usb_ep_free_request(fu->ep_status, stream->req_status);

	stream->req_in = NULL;
	stream->req_out = NULL;
	stream->req_status = NULL;
}

static void uasp_free_cmdreq(struct f_uas *fu)
{
	usb_ep_free_request(fu->ep_cmd, fu->cmd.req);
	kfree(fu->cmd.buf);
	fu->cmd.req = NULL;
	fu->cmd.buf = NULL;
}

void uasp_cleanup_old_alt(struct f_uas *fu)
{
	int i;

	if (!(fu->flags & USBG_ENABLED))
		return;

	usb_ep_disable(fu->ep_in);
	usb_ep_disable(fu->ep_out);
	usb_ep_disable(fu->ep_status);
	usb_ep_disable(fu->ep_cmd);

	for (i = 0; i < UASP_SS_EP_COMP_NUM_STREAMS; i++)
		uasp_cleanup_one_stream(fu, &fu->stream[i]);
	uasp_free_cmdreq(fu);
}

static void uasp_status_data_cmpl(struct usb_ep *ep, struct usb_request *req);
static int uasp_prepare_r_request(struct usbg_cmd *cmd)
{
	struct se_cmd *se_cmd = &cmd->se_cmd;
	struct f_uas *fu = cmd->fu;
	struct usb_gadget *gadget = fuas_to_gadget(fu);
	struct uas_stream *stream = cmd->stream;

	if (!gadget->sg_supported) {
		cmd->data_buf = kmalloc(se_cmd->data_length, GFP_ATOMIC);
		if (!cmd->data_buf)
			return -ENOMEM;

		sg_copy_to_buffer(se_cmd->t_data_sg,
				se_cmd->t_data_nents,
				cmd->data_buf,
				se_cmd->data_length);

		stream->req_in->buf = cmd->data_buf;
	} else {
		stream->req_in->buf = NULL;
		stream->req_in->num_sgs = se_cmd->t_data_nents;
		stream->req_in->sg = se_cmd->t_data_sg;
	}

	stream->req_in->complete = uasp_status_data_cmpl;
	stream->req_in->length = se_cmd->data_length;
	stream->req_in->context = cmd;

	cmd->state = UASP_SEND_STATUS;
	return 0;
}

static void uasp_prepare_status(struct usbg_cmd *cmd)
{
	struct se_cmd *se_cmd = &cmd->se_cmd;
	struct sense_iu *iu = &cmd->sense_iu;
	struct uas_stream *stream = cmd->stream;

	cmd->state = UASP_QUEUE_COMMAND;
	iu->iu_id = IU_ID_STATUS;
	iu->tag = cpu_to_be16(cmd->tag);

	/*
	 * iu->status_qual = cpu_to_be16(STATUS QUALIFIER SAM-4. Where R U?);
	 */
	iu->len = cpu_to_be16(se_cmd->scsi_sense_length);
	iu->status = se_cmd->scsi_status;
	stream->req_status->context = cmd;
	stream->req_status->length = se_cmd->scsi_sense_length + 16;
	stream->req_status->buf = iu;
	stream->req_status->complete = uasp_status_data_cmpl;
}

static void uasp_status_data_cmpl(struct usb_ep *ep, struct usb_request *req)
{
	struct usbg_cmd *cmd = req->context;
	struct uas_stream *stream = cmd->stream;
	struct f_uas *fu = cmd->fu;
	int ret;

	if (req->status < 0)
		goto cleanup;

	switch (cmd->state) {
	case UASP_SEND_DATA:
		ret = uasp_prepare_r_request(cmd);
		if (ret)
			goto cleanup;
		ret = usb_ep_queue(fu->ep_in, stream->req_in, GFP_ATOMIC);
		if (ret)
			pr_err("%s(%d) => %d\n", __func__, __LINE__, ret);
		break;

	case UASP_RECEIVE_DATA:
		ret = usbg_prepare_w_request(cmd, stream->req_out);
		if (ret)
			goto cleanup;
		ret = usb_ep_queue(fu->ep_out, stream->req_out, GFP_ATOMIC);
		if (ret)
			pr_err("%s(%d) => %d\n", __func__, __LINE__, ret);
		break;

	case UASP_SEND_STATUS:
		uasp_prepare_status(cmd);
		ret = usb_ep_queue(fu->ep_status, stream->req_status,
				GFP_ATOMIC);
		if (ret)
			pr_err("%s(%d) => %d\n", __func__, __LINE__, ret);
		break;

	case UASP_QUEUE_COMMAND:
		usbg_cleanup_cmd(cmd);
		usb_ep_queue(fu->ep_cmd, fu->cmd.req, GFP_ATOMIC);
		break;

	default:
		BUG();
	};
	return;

cleanup:
	usbg_cleanup_cmd(cmd);
}

int uasp_send_status_response(struct usbg_cmd *cmd)
{
	struct f_uas *fu = cmd->fu;
	struct uas_stream *stream = cmd->stream;
	struct sense_iu *iu = &cmd->sense_iu;

	iu->tag = cpu_to_be16(cmd->tag);
	stream->req_status->complete = uasp_status_data_cmpl;
	stream->req_status->context = cmd;
	cmd->fu = fu;
	uasp_prepare_status(cmd);
	return usb_ep_queue(fu->ep_status, stream->req_status, GFP_ATOMIC);
}

int uasp_send_read_response(struct usbg_cmd *cmd)
{
	struct f_uas *fu = cmd->fu;
	struct uas_stream *stream = cmd->stream;
	struct sense_iu *iu = &cmd->sense_iu;
	int ret;

	cmd->fu = fu;

	iu->tag = cpu_to_be16(cmd->tag);
	if (fu->flags & USBG_USE_STREAMS) {

		ret = uasp_prepare_r_request(cmd);
		if (ret)
			goto out;
		ret = usb_ep_queue(fu->ep_in, stream->req_in, GFP_ATOMIC);
		if (ret) {
			pr_err("%s(%d) => %d\n", __func__, __LINE__, ret);
			kfree(cmd->data_buf);
			cmd->data_buf = NULL;
		}

	} else {

		iu->iu_id = IU_ID_READ_READY;
		iu->tag = cpu_to_be16(cmd->tag);

		stream->req_status->complete = uasp_status_data_cmpl;
		stream->req_status->context = cmd;

		cmd->state = UASP_SEND_DATA;
		stream->req_status->buf = iu;
		stream->req_status->length = sizeof(struct iu);

		ret = usb_ep_queue(fu->ep_status, stream->req_status,
				GFP_ATOMIC);
		if (ret)
			pr_err("%s(%d) => %d\n", __func__, __LINE__, ret);
	}
out:
	return ret;
}

int uasp_send_write_request(struct usbg_cmd *cmd)
{
	struct f_uas *fu = cmd->fu;
	struct se_cmd *se_cmd = &cmd->se_cmd;
	struct uas_stream *stream = cmd->stream;
	struct sense_iu *iu = &cmd->sense_iu;
	int ret;

	init_completion(&cmd->write_complete);
	cmd->fu = fu;

	iu->tag = cpu_to_be16(cmd->tag);

	if (fu->flags & USBG_USE_STREAMS) {

		ret = usbg_prepare_w_request(cmd, stream->req_out);
		if (ret)
			goto cleanup;
		ret = usb_ep_queue(fu->ep_out, stream->req_out, GFP_ATOMIC);
		if (ret)
			pr_err("%s(%d)\n", __func__, __LINE__);

	} else {

		iu->iu_id = IU_ID_WRITE_READY;
		iu->tag = cpu_to_be16(cmd->tag);

		stream->req_status->complete = uasp_status_data_cmpl;
		stream->req_status->context = cmd;

		cmd->state = UASP_RECEIVE_DATA;
		stream->req_status->buf = iu;
		stream->req_status->length = sizeof(struct iu);

		ret = usb_ep_queue(fu->ep_status, stream->req_status,
				GFP_ATOMIC);
		if (ret)
			pr_err("%s(%d)\n", __func__, __LINE__);
	}

	wait_for_completion(&cmd->write_complete);
	transport_generic_process_write(se_cmd);
cleanup:
	return ret;
}

static void uasp_cmd_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_uas *fu = req->context;
	int ret;

	if (req->status < 0)
		return;

	ret = usbg_submit_command(fu, req->buf, req->actual);
	/*
	 * Once we tune for performance enqueue the command req here again so
	 * we can receive a second command while we processing this one. Pay
	 * attention to properly sync STAUS endpoint with DATA IN + OUT so you
	 * don't break HS.
	 */
	if (!ret)
		return;
	usb_ep_queue(fu->ep_cmd, fu->cmd.req, GFP_ATOMIC);
}

static int uasp_alloc_stream_res(struct f_uas *fu, struct uas_stream *stream)
{
	stream->req_in = usb_ep_alloc_request(fu->ep_in, GFP_KERNEL);
	if (!stream->req_in)
		goto out;

	stream->req_out = usb_ep_alloc_request(fu->ep_out, GFP_KERNEL);
	if (!stream->req_out)
		goto err_out;

	stream->req_status = usb_ep_alloc_request(fu->ep_status, GFP_KERNEL);
	if (!stream->req_status)
		goto err_sts;

	return 0;
err_sts:
	usb_ep_free_request(fu->ep_status, stream->req_status);
	stream->req_status = NULL;
err_out:
	usb_ep_free_request(fu->ep_out, stream->req_out);
	stream->req_out = NULL;
out:
	return -ENOMEM;
}

static int uasp_alloc_cmd(struct f_uas *fu)
{
	fu->cmd.req = usb_ep_alloc_request(fu->ep_cmd, GFP_KERNEL);
	if (!fu->cmd.req)
		goto err;

	fu->cmd.buf = kmalloc(fu->ep_cmd->maxpacket, GFP_KERNEL);
	if (!fu->cmd.buf)
		goto err_buf;

	fu->cmd.req->complete = uasp_cmd_complete;
	fu->cmd.req->buf = fu->cmd.buf;
	fu->cmd.req->length = fu->ep_cmd->maxpacket;
	fu->cmd.req->context = fu;
	return 0;

err_buf:
	usb_ep_free_request(fu->ep_cmd, fu->cmd.req);
err:
	return -ENOMEM;
}

static void uasp_setup_stream_res(struct f_uas *fu, int max_streams)
{
	int i;

	for (i = 0; i < max_streams; i++) {
		struct uas_stream *s = &fu->stream[i];

		s->req_in->stream_id = i + 1;
		s->req_out->stream_id = i + 1;
		s->req_status->stream_id = i + 1;
	}
}

static int uasp_prepare_reqs(struct f_uas *fu)
{
	int ret;
	int i;
	int max_streams;

	if (fu->flags & USBG_USE_STREAMS)
		max_streams = UASP_SS_EP_COMP_NUM_STREAMS;
	else
		max_streams = 1;

	for (i = 0; i < max_streams; i++) {
		ret = uasp_alloc_stream_res(fu, &fu->stream[i]);
		if (ret)
			goto err_cleanup;
	}

	ret = uasp_alloc_cmd(fu);
	if (ret)
		goto err_free_stream;
	uasp_setup_stream_res(fu, max_streams);

	ret = usb_ep_queue(fu->ep_cmd, fu->cmd.req, GFP_ATOMIC);
	if (ret)
		goto err_free_stream;

	return 0;

err_free_stream:
	uasp_free_cmdreq(fu);

err_cleanup:
	if (i) {
		do {
			uasp_cleanup_one_stream(fu, &fu->stream[i - 1]);
			i--;
		} while (i);
	}
	pr_err("UASP: endpoint setup failed\n");
	return ret;
}

void uasp_set_alt(struct f_uas *fu)
{
	struct usb_function *f = &fu->function;
	struct usb_gadget *gadget = f->config->cdev->gadget;
	int ret;

	fu->flags = USBG_IS_UAS;

	if (gadget->speed == USB_SPEED_SUPER)
		fu->flags |= USBG_USE_STREAMS;

	config_ep_by_speed(gadget, f, fu->ep_in);
	ret = usb_ep_enable(fu->ep_in);
	if (ret)
		goto err_b_in;

	config_ep_by_speed(gadget, f, fu->ep_out);
	ret = usb_ep_enable(fu->ep_out);
	if (ret)
		goto err_b_out;

	config_ep_by_speed(gadget, f, fu->ep_cmd);
	ret = usb_ep_enable(fu->ep_cmd);
	if (ret)
		goto err_cmd;
	config_ep_by_speed(gadget, f, fu->ep_status);
	ret = usb_ep_enable(fu->ep_status);
	if (ret)
		goto err_status;

	ret = uasp_prepare_reqs(fu);
	if (ret)
		goto err_wq;
	fu->flags |= USBG_ENABLED;

	pr_info("Using the UAS protocol\n");
	return;
err_wq:
	usb_ep_disable(fu->ep_status);
err_status:
	usb_ep_disable(fu->ep_cmd);
err_cmd:
	usb_ep_disable(fu->ep_out);
err_b_out:
	usb_ep_disable(fu->ep_in);
err_b_in:
	fu->flags = 0;
}
