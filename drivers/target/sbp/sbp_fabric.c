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

#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/firewire.h>

#include <asm/unaligned.h>

#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/libfc.h>

#include <target/target_core_base.h>

#include "sbp_base.h"
#include "sbp_fabric.h"

int sbp_check_true(struct se_portal_group *se_tpg)
{
	return 1;
}

int sbp_check_false(struct se_portal_group *se_tpg)
{
	return 0;
}

char *sbp_get_fabric_name(void)
{
	return "sbp";
}

char *sbp_get_fabric_wwn(struct se_portal_group *se_tpg)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;

	return &tport->tport_name[0];
}

u16 sbp_get_tag(struct se_portal_group *se_tpg)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	return tpg->tport_tpgt;
}

u32 sbp_get_default_depth(struct se_portal_group *se_tpg)
{
	return 1;
}

struct se_node_acl *sbp_alloc_fabric_acl(struct se_portal_group *se_tpg)
{
	struct sbp_nacl *nacl;

	nacl = kzalloc(sizeof(struct sbp_nacl), GFP_KERNEL);
	if (!nacl) {
		pr_err("Unable to alocate struct sbp_nacl\n");
		return NULL;
	}

	return &nacl->se_node_acl;
}

void sbp_release_fabric_acl(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl)
{
	struct sbp_nacl *nacl =
		container_of(se_nacl, struct sbp_nacl, se_node_acl);
	kfree(nacl);
}

u32 sbp_tpg_get_inst_index(struct se_portal_group *se_tpg)
{
	return 1;
}

void sbp_release_cmd(struct se_cmd *se_cmd)
{
	return;
}

int sbp_shutdown_session(struct se_session *se_sess)
{
	return 0;
}

void sbp_close_session(struct se_session *se_sess)
{
	return;
}

void sbp_stop_session(struct se_session *se_sess, int sess_sleep,
		int conn_sleep)
{
	return;
}

void sbp_reset_nexus(struct se_session *se_sess)
{
	return;
}

int sbp_sess_logged_in(struct se_session *se_sess)
{
	return 0;
}

u32 sbp_sess_get_index(struct se_session *se_sess)
{
	return 0;
}

int sbp_write_pending(struct se_cmd *se_cmd)
{
	return 0;
}

int sbp_write_pending_status(struct se_cmd *se_cmd)
{
	return 0;
}

void sbp_set_default_node_attrs(struct se_node_acl *nacl)
{
	return;
}

u32 sbp_get_task_tag(struct se_cmd *se_cmd)
{
	return 0;
}

int sbp_get_cmd_state(struct se_cmd *se_cmd)
{
	return 0;
}

int sbp_queue_data_in(struct se_cmd *se_cmd)
{
	return 0;
}

int sbp_queue_status(struct se_cmd *se_cmd)
{
	return 0;
}

int sbp_queue_tm_rsp(struct se_cmd *se_cmd)
{
	return 0;
}

u16 sbp_set_fabric_sense_len(struct se_cmd *se_cmd, u32 sense_length)
{
	return 0;
}

u16 sbp_get_fabric_sense_len(void)
{
	return 0;
}

int sbp_is_state_remove(struct se_cmd *se_cmd)
{
	return 0;
}

