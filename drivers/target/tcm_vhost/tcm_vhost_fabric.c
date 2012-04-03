/*******************************************************************************
 * © Copyright 2011 RisingTide Systems LLC.
 *
 * Licensed to the Linux Foundation under the General Public License (GPL) version 2. 
 * 
 * Author: Nicholas A. Bellinger <nab@risingtidesystems.com>
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
 ****************************************************************************/

#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <asm/unaligned.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/libfc.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h> /* TODO vhost.h currently depends on this */
#include <linux/virtio_scsi.h>
#include "../../vhost/vhost.h" /* TODO this is ugly */

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_configfs.h>

#include "tcm_vhost_base.h"
#include "tcm_vhost_fabric.h"
#include "tcm_vhost_scsi.h"

int tcm_vhost_check_true(struct se_portal_group *se_tpg)
{
	return 1;
}

int tcm_vhost_check_false(struct se_portal_group *se_tpg)
{
	return 0;
}

char *tcm_vhost_get_fabric_name(void)
{
	return "vhost";
}

u8 tcm_vhost_get_fabric_proto_ident(struct se_portal_group *se_tpg)
{
	struct tcm_vhost_tpg *tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);
	struct tcm_vhost_tport *tport = tpg->tport;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
		return sas_get_fabric_proto_ident(se_tpg);
	case SCSI_PROTOCOL_FCP:
		return fc_get_fabric_proto_ident(se_tpg);
	case SCSI_PROTOCOL_ISCSI:
		return iscsi_get_fabric_proto_ident(se_tpg);
	default:
		pr_err("Unknown tport_proto_id: 0x%02x, using"
			" SAS emulation\n", tport->tport_proto_id);
		break;
	}

	return sas_get_fabric_proto_ident(se_tpg);
}

char *tcm_vhost_get_fabric_wwn(struct se_portal_group *se_tpg)
{
	struct tcm_vhost_tpg *tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);
	struct tcm_vhost_tport *tport = tpg->tport;

	return &tport->tport_name[0];
}

u16 tcm_vhost_get_tag(struct se_portal_group *se_tpg)
{
	struct tcm_vhost_tpg *tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);
	return tpg->tport_tpgt;
}

u32 tcm_vhost_get_default_depth(struct se_portal_group *se_tpg)
{
	return 1;
}

u32 tcm_vhost_get_pr_transport_id(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct t10_pr_registration *pr_reg,
	int *format_code,
	unsigned char *buf)
{
	struct tcm_vhost_tpg *tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);
	struct tcm_vhost_tport *tport = tpg->tport;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
		return sas_get_pr_transport_id(se_tpg, se_nacl, pr_reg,
					format_code, buf);
	case SCSI_PROTOCOL_FCP:
		return fc_get_pr_transport_id(se_tpg, se_nacl, pr_reg,
					format_code, buf);
	case SCSI_PROTOCOL_ISCSI:
		return iscsi_get_pr_transport_id(se_tpg, se_nacl, pr_reg,
					format_code, buf);
	default:
		pr_err("Unknown tport_proto_id: 0x%02x, using"
			" SAS emulation\n", tport->tport_proto_id);
		break;	
	}

	return sas_get_pr_transport_id(se_tpg, se_nacl, pr_reg,
			format_code, buf);
}

u32 tcm_vhost_get_pr_transport_id_len(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct t10_pr_registration *pr_reg,
	int *format_code)
{
	struct tcm_vhost_tpg *tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);
	struct tcm_vhost_tport *tport = tpg->tport;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
		return sas_get_pr_transport_id_len(se_tpg, se_nacl, pr_reg,
					format_code);
	case SCSI_PROTOCOL_FCP:
		return fc_get_pr_transport_id_len(se_tpg, se_nacl, pr_reg,
					format_code);
	case SCSI_PROTOCOL_ISCSI:
		return iscsi_get_pr_transport_id_len(se_tpg, se_nacl, pr_reg,
					format_code);
	default:
		pr_err("Unknown tport_proto_id: 0x%02x, using"
			" SAS emulation\n", tport->tport_proto_id);
		break;
	}

	return sas_get_pr_transport_id_len(se_tpg, se_nacl, pr_reg,
			format_code);
}

char *tcm_vhost_parse_pr_out_transport_id(
	struct se_portal_group *se_tpg,
	const char *buf,
	u32 *out_tid_len,
	char **port_nexus_ptr)
{
	struct tcm_vhost_tpg *tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);
	struct tcm_vhost_tport *tport = tpg->tport;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
		return sas_parse_pr_out_transport_id(se_tpg, buf, out_tid_len,
					port_nexus_ptr);
	case SCSI_PROTOCOL_FCP:
		return fc_parse_pr_out_transport_id(se_tpg, buf, out_tid_len,
					port_nexus_ptr);
	case SCSI_PROTOCOL_ISCSI:
		return iscsi_parse_pr_out_transport_id(se_tpg, buf, out_tid_len,
					port_nexus_ptr);
	default:
		pr_err("Unknown tport_proto_id: 0x%02x, using"
			" SAS emulation\n", tport->tport_proto_id);
		break;
	}

	return sas_parse_pr_out_transport_id(se_tpg, buf, out_tid_len,
			port_nexus_ptr);
}

struct se_node_acl *tcm_vhost_alloc_fabric_acl(struct se_portal_group *se_tpg)
{
	struct tcm_vhost_nacl *nacl;

	nacl = kzalloc(sizeof(struct tcm_vhost_nacl), GFP_KERNEL);
	if (!nacl) {
		pr_err("Unable to alocate struct tcm_vhost_nacl\n");
		return NULL;
	}

	return &nacl->se_node_acl;
}

void tcm_vhost_release_fabric_acl(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl)
{
	struct tcm_vhost_nacl *nacl = container_of(se_nacl,
			struct tcm_vhost_nacl, se_node_acl);
	kfree(nacl);
}

u32 tcm_vhost_tpg_get_inst_index(struct se_portal_group *se_tpg)
{
	return 1;
}

/*
 * Called by struct target_core_fabric_ops->new_cmd_map()
 *
 * Always called in process context.  A non zero return value
 * here will signal to handle an exception based on the return code.
 */
int tcm_vhost_new_cmd_map(struct se_cmd *se_cmd)
{
	struct tcm_vhost_cmd *tv_cmd = container_of(se_cmd,
				struct tcm_vhost_cmd, tvc_se_cmd);
	struct scatterlist *sg_ptr, *sg_bidi_ptr = NULL;
	u32 sg_no_bidi = 0;
	int ret;
	/*
	 * Allocate the necessary tasks to complete the received CDB+data
	 */
	ret = target_setup_cmd_from_cdb(se_cmd, tv_cmd->tvc_cdb);
	if (ret != 0)
		return ret;
	/*
	 * Setup the struct scatterlist memory from the received
	 * struct tcm_vhost_cmd..
	 */
	if (tv_cmd->tvc_sgl_count) {
		sg_ptr = tv_cmd->tvc_sgl;
		/*
		 * For BIDI commands, pass in the extra READ buffer
		 * to transport_generic_map_mem_to_cmd() below..
		 */
#warning FIXME: Fix BIDI operation in tcm_vhost_new_cmd_map()
#if 0
		if (se_cmd->se_cmd_flags & SCF_BIDI) {
			mem_bidi_ptr = NULL;
			sg_no_bidi = 0;
		}
#endif
	} else {
		/*
		 * Used for DMA_NONE
		 */
		sg_ptr = NULL;
	}

	/* Tell the core about our preallocated memory */
	return transport_generic_map_mem_to_cmd(se_cmd, sg_ptr,
				tv_cmd->tvc_sgl_count, sg_bidi_ptr,
				sg_no_bidi);
}

void tcm_vhost_release_cmd(struct se_cmd *se_cmd)
{
	return;
}

int tcm_vhost_shutdown_session(struct se_session *se_sess)
{
	return 0;
}

void tcm_vhost_close_session(struct se_session *se_sess)
{
	return;
}

u32 tcm_vhost_sess_get_index(struct se_session *se_sess)
{
	return 0;
}

int tcm_vhost_write_pending(struct se_cmd *se_cmd)
{
	/* Go ahead and process the write immediately */
	transport_generic_process_write(se_cmd);
	return 0;
}

int tcm_vhost_write_pending_status(struct se_cmd *se_cmd)
{
	return 0;
}

void tcm_vhost_set_default_node_attrs(struct se_node_acl *nacl)
{
	return;
}

u32 tcm_vhost_get_task_tag(struct se_cmd *se_cmd)
{
	return 0;
}

int tcm_vhost_get_cmd_state(struct se_cmd *se_cmd)
{
	return 0;
}

int tcm_vhost_queue_data_in(struct se_cmd *se_cmd)
{
	struct tcm_vhost_cmd *tv_cmd = container_of(se_cmd,
				struct tcm_vhost_cmd, tvc_se_cmd);
	vhost_scsi_complete_cmd(tv_cmd);
	return 0;
}

int tcm_vhost_queue_status(struct se_cmd *se_cmd)
{
	struct tcm_vhost_cmd *tv_cmd = container_of(se_cmd,
				struct tcm_vhost_cmd, tvc_se_cmd);
	vhost_scsi_complete_cmd(tv_cmd);
	return 0;
}

int tcm_vhost_queue_tm_rsp(struct se_cmd *se_cmd)
{
	return 0;
}

u16 tcm_vhost_set_fabric_sense_len(struct se_cmd *se_cmd, u32 sense_length)
{
	return 0;
}

u16 tcm_vhost_get_fabric_sense_len(void)
{
	return 0;
}
