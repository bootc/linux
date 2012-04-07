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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/configfs.h>
#include <linux/ctype.h>
#include <linux/firewire.h>

#include <asm/unaligned.h>

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include <target/target_core_configfs.h>
#include <target/target_core_fabric_configfs.h>
#include <target/configfs_macros.h>

#include "sbp_base.h"
#include "sbp_fabric.h"
#include "sbp_management_agent.h"

/* Local pointer to allocated TCM configfs fabric module */
struct target_fabric_configfs *sbp_fabric_configfs;

/* FireWire address region for management and command block address handlers */
const struct fw_address_region sbp_register_region = {
	.start = CSR_REGISTER_BASE + 0x10000,
	.end   = 0x1000000000000ULL,
};

static const u32 sbp_unit_directory_template[] = {
	0x1200609e, /* unit_specifier_id: NCITS/T10 */
	0x13010483, /* unit_sw_version: 1155D Rev 4 */
	0x3800609e, /* command_set_specifier_id: NCITS/T10 */
	0x390104d8, /* command_set: SPC-2 */
	0x3b000000, /* command_set_revision: 0 */
	0x3c000001, /* firmware_revision: 1 */
};

static int sbp_count_se_tpg_luns(struct se_portal_group *tpg)
{
	int i, count = 0;

	spin_lock(&tpg->tpg_lun_lock);
	for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
		struct se_lun *se_lun = tpg->tpg_lun_list[i];

		if (se_lun->lun_status == TRANSPORT_LUN_STATUS_FREE)
			continue;

		count++;
	}
	spin_unlock(&tpg->tpg_lun_lock);

	return count;
}

static int sbp_update_unit_directory(struct sbp_tport *tport)
{
	int num_luns, num_entries, idx = 0, mgt_agt_addr, ret, i;
	u32 *data;

	if (tport->unit_directory.data) {
		fw_core_remove_descriptor(&tport->unit_directory);
		kfree(tport->unit_directory.data);
		tport->unit_directory.data = NULL;
	}

	if (!tport->enable || !tport->tpg)
		return 0;

	num_luns = sbp_count_se_tpg_luns(&tport->tpg->se_tpg);

	/*
	 * Number of entries in the final unit directory:
	 *  - all of those in the template
	 *  - management_agent
	 *  - unit_characteristics
	 *  - reconnect_timeout
	 *  - unit unique ID
	 *  - one for each LUN
	 *
	 *  MUST NOT include leaf or sub-directory entries
	 */
	num_entries = ARRAY_SIZE(sbp_unit_directory_template) + 4 + num_luns;

	if (tport->directory_id != -1)
		num_entries++;

	/* allocate num_entries + 4 for the header and unique ID leaf */
	data = kcalloc((num_entries + 4), sizeof(u32), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* directory_length */
	data[idx++] = num_entries << 16;

	/* directory_id */
	if (tport->directory_id != -1)
		data[idx++] = (CSR_DIRECTORY_ID << 24) | tport->directory_id;

	/* unit directory template */
	memcpy(&data[idx], sbp_unit_directory_template,
			sizeof(sbp_unit_directory_template));
	idx += ARRAY_SIZE(sbp_unit_directory_template);

	/* management_agent */
	mgt_agt_addr = (tport->mgt_agt->handler.offset - CSR_REGISTER_BASE) / 4;
	data[idx++] = 0x54000000 | (mgt_agt_addr & 0x00ffffff);

	/* unit_characteristics */
	data[idx++] = 0x3a000000 |
		(((tport->mgt_orb_timeout * 2) << 8) & 0xff00) |
		SBP_ORB_FETCH_SIZE;

	/* reconnect_timeout */
	data[idx++] = 0x3d000000 | (tport->max_reconnect_timeout & 0xffff);

	/* unit unique ID (leaf is just after LUNs) */
	data[idx++] = 0x8d000000 | (num_luns + 1);

	spin_lock(&tport->tpg->se_tpg.tpg_lun_lock);
	for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
		struct se_lun *se_lun = tport->tpg->se_tpg.tpg_lun_list[i];
		struct se_device *dev;
		int type;

		if (se_lun->lun_status == TRANSPORT_LUN_STATUS_FREE)
			continue;

		spin_unlock(&tport->tpg->se_tpg.tpg_lun_lock);

		dev = se_lun->lun_se_dev;
		type = dev->transport->get_device_type(dev);

		/* logical_unit_number */
		data[idx++] = 0x14000000 |
			((type << 16) & 0x1f0000) |
			(se_lun->unpacked_lun & 0xffff);

		spin_lock(&tport->tpg->se_tpg.tpg_lun_lock);
	}
	spin_unlock(&tport->tpg->se_tpg.tpg_lun_lock);

	/* unit unique ID leaf */
	data[idx++] = 2 << 16;
	data[idx++] = tport->guid >> 32;
	data[idx++] = tport->guid;

	tport->unit_directory.length = idx;
	tport->unit_directory.key = (CSR_DIRECTORY | CSR_UNIT) << 24;
	tport->unit_directory.data = data;

	ret = fw_core_add_descriptor(&tport->unit_directory);
	if (ret < 0) {
		kfree(tport->unit_directory.data);
		tport->unit_directory.data = NULL;
	}

	return ret;
}

static ssize_t sbp_parse_wwn(const char *name, u64 *wwn, int strict)
{
	const char *cp;
	char c, nibble;
	int pos = 0, err;

	*wwn = 0;
	for (cp = name; cp < &name[SBP_NAMELEN - 1]; cp++) {
		c = *cp;
		if (c == '\n' && cp[1] == '\0')
			continue;
		if (c == '\0') {
			err = 2;
			if (pos != 16)
				goto fail;
			return cp - name;
		}
		err = 3;
		if (isdigit(c))
			nibble = c - '0';
		else if (isxdigit(c) && (islower(c) || !strict))
			nibble = tolower(c) - 'a' + 10;
		else
			goto fail;
		*wwn = (*wwn << 4) | nibble;
		pos++;
	}
	err = 4;
fail:
	printk(KERN_INFO "err %u len %zu pos %u\n",
			err, cp - name, pos);
	return -1;
}

static ssize_t sbp_format_wwn(char *buf, size_t len, u64 wwn)
{
	return snprintf(buf, len, "%016llx", wwn);
}

static struct se_node_acl *sbp_make_nodeacl(
		struct se_portal_group *se_tpg,
		struct config_group *group,
		const char *name)
{
	struct se_node_acl *se_nacl, *se_nacl_new;
	struct sbp_nacl *nacl;
	u64 guid = 0;
	u32 nexus_depth = 1;

	if (sbp_parse_wwn(name, &guid, 1) < 0)
		return ERR_PTR(-EINVAL);

	se_nacl_new = sbp_alloc_fabric_acl(se_tpg);
	if (!se_nacl_new)
		return ERR_PTR(-ENOMEM);

	/*
	 * se_nacl_new may be released by core_tpg_add_initiator_node_acl()
	 * when converting a NodeACL from demo mode -> explict
	 */
	se_nacl = core_tpg_add_initiator_node_acl(se_tpg, se_nacl_new,
			name, nexus_depth);
	if (IS_ERR(se_nacl)) {
		sbp_release_fabric_acl(se_tpg, se_nacl_new);
		return se_nacl;
	}

	nacl = container_of(se_nacl, struct sbp_nacl, se_node_acl);
	nacl->guid = guid;
	sbp_format_wwn(nacl->iport_name, SBP_NAMELEN, guid);

	return se_nacl;
}

static void sbp_drop_nodeacl(struct se_node_acl *se_acl)
{
	struct sbp_nacl *nacl =
		container_of(se_acl, struct sbp_nacl, se_node_acl);

	core_tpg_del_initiator_node_acl(se_acl->se_tpg, se_acl, 1);
	kfree(nacl);
}

static int sbp_post_link_lun(
		struct se_portal_group *se_tpg,
		struct se_lun *se_lun)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);

	return sbp_update_unit_directory(tpg->tport);
}

static void sbp_pre_unlink_lun(
		struct se_portal_group *se_tpg,
		struct se_lun *se_lun)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;
	int ret;

	if (sbp_count_se_tpg_luns(&tpg->se_tpg) == 0)
		tport->enable = 0;

	ret = sbp_update_unit_directory(tport);
	if (ret < 0)
		pr_err("unlink LUN: failed to update unit directory\n");
}

static struct se_portal_group *sbp_make_tpg(
		struct se_wwn *wwn,
		struct config_group *group,
		const char *name)
{
	struct sbp_tport *tport =
		container_of(wwn, struct sbp_tport, tport_wwn);

	struct sbp_tpg *tpg;
	unsigned long tpgt;
	int ret;

	if (strstr(name, "tpgt_") != name)
		return ERR_PTR(-EINVAL);
	if (kstrtoul(name + 5, 10, &tpgt) || tpgt > UINT_MAX)
		return ERR_PTR(-EINVAL);

	if (tport->tpg) {
		pr_err("Only one TPG per Unit is possible.\n");
		return ERR_PTR(-EBUSY);
	}

	tpg = kzalloc(sizeof(*tpg), GFP_KERNEL);
	if (!tpg) {
		pr_err("Unable to allocate struct sbp_tpg\n");
		return ERR_PTR(-ENOMEM);
	}

	tpg->tport = tport;
	tpg->tport_tpgt = tpgt;
	tport->tpg = tpg;

	/* default attribute values */
	tport->enable = 0;
	tport->directory_id = -1;
	tport->mgt_orb_timeout = 15;
	tport->max_reconnect_timeout = 5;
	tport->max_logins_per_lun = 1;

	tport->mgt_agt = sbp_management_agent_register(tport);
	if (IS_ERR(tport->mgt_agt)) {
		ret = PTR_ERR(tport->mgt_agt);
		kfree(tpg);
		return ERR_PTR(ret);
	}

	ret = core_tpg_register(&sbp_fabric_configfs->tf_ops, wwn,
			&tpg->se_tpg, (void *)tpg,
			TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0) {
		sbp_management_agent_unregister(tport->mgt_agt);
		kfree(tpg);
		return ERR_PTR(ret);
	}

	return &tpg->se_tpg;
}

static void sbp_drop_tpg(struct se_portal_group *se_tpg)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;

	core_tpg_deregister(se_tpg);
	sbp_management_agent_unregister(tport->mgt_agt);
	tport->tpg = NULL;
	kfree(tpg);
}

static struct se_wwn *sbp_make_tport(
		struct target_fabric_configfs *tf,
		struct config_group *group,
		const char *name)
{
	struct sbp_tport *tport;
	u64 guid = 0;

	if (sbp_parse_wwn(name, &guid, 1) < 0)
		return ERR_PTR(-EINVAL);

	tport = kzalloc(sizeof(*tport), GFP_KERNEL);
	if (!tport) {
		pr_err("Unable to allocate struct sbp_tport\n");
		return ERR_PTR(-ENOMEM);
	}

	tport->guid = guid;
	sbp_format_wwn(tport->tport_name, SBP_NAMELEN, guid);

	return &tport->tport_wwn;
}

static void sbp_drop_tport(struct se_wwn *wwn)
{
	struct sbp_tport *tport =
		container_of(wwn, struct sbp_tport, tport_wwn);

	kfree(tport);
}

static ssize_t sbp_wwn_show_attr_version(
		struct target_fabric_configfs *tf,
		char *page)
{
	return sprintf(page, "FireWire SBP fabric module %s\n", SBP_VERSION);
}

TF_WWN_ATTR_RO(sbp, version);

static struct configfs_attribute *sbp_wwn_attrs[] = {
	&sbp_wwn_version.attr,
	NULL,
};

static ssize_t sbp_tpg_show_directory_id(
		struct se_portal_group *se_tpg,
		char *page)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;

	if (tport->directory_id == -1)
		return sprintf(page, "implicit\n");
	else
		return sprintf(page, "%06x\n", tport->directory_id);
}

static ssize_t sbp_tpg_store_directory_id(
		struct se_portal_group *se_tpg,
		const char *page,
		size_t count)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;
	unsigned long val;

	if (tport->enable) {
		pr_err("Cannot change the directory_id on an active target.\n");
		return -EBUSY;
	}

	if (strstr(page, "implicit") == page) {
		tport->directory_id = -1;
	} else {
		if (kstrtoul(page, 16, &val) < 0)
			return -EINVAL;
		if (val > 0xffffff)
			return -EINVAL;

		tport->directory_id = val;
	}

	return count;
}

static ssize_t sbp_tpg_show_enable(
		struct se_portal_group *se_tpg,
		char *page)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;
	return sprintf(page, "%d\n", tport->enable);
}

static ssize_t sbp_tpg_store_enable(
		struct se_portal_group *se_tpg,
		const char *page,
		size_t count)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;
	unsigned long val;
	int ret;

	if (kstrtoul(page, 0, &val) < 0)
		return -EINVAL;
	if ((val != 0) && (val != 1))
		return -EINVAL;

	if (tport->enable == val)
		return count;

	if (val) {
		if (sbp_count_se_tpg_luns(&tpg->se_tpg) == 0) {
			pr_err("Cannot enable a target with no LUNs!\n");
			return -EINVAL;
		}
	} else {
		/* XXX: force-shutdown sessions instead? */
		spin_lock_bh(&se_tpg->session_lock);
		if (!list_empty(&se_tpg->tpg_sess_list)) {
			spin_unlock_bh(&se_tpg->session_lock);
			return -EBUSY;
		}
		spin_unlock_bh(&se_tpg->session_lock);
	}

	tport->enable = val;

	ret = sbp_update_unit_directory(tport);
	if (ret < 0) {
		pr_err("Could not update Config ROM\n");
		return ret;
	}

	return count;
}

TF_TPG_BASE_ATTR(sbp, directory_id, S_IRUGO | S_IWUSR);
TF_TPG_BASE_ATTR(sbp, enable, S_IRUGO | S_IWUSR);

static struct configfs_attribute *sbp_tpg_base_attrs[] = {
	&sbp_tpg_directory_id.attr,
	&sbp_tpg_enable.attr,
	NULL,
};

static ssize_t sbp_tpg_attrib_show_mgt_orb_timeout(
		struct se_portal_group *se_tpg,
		char *page)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;
	return sprintf(page, "%d\n", tport->mgt_orb_timeout);
}

static ssize_t sbp_tpg_attrib_store_mgt_orb_timeout(
		struct se_portal_group *se_tpg,
		const char *page,
		size_t count)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;
	unsigned long val;
	int ret;

	if (kstrtoul(page, 0, &val) < 0)
		return -EINVAL;
	if ((val < 1) || (val > 127))
		return -EINVAL;

	if (tport->mgt_orb_timeout == val)
		return count;

	tport->mgt_orb_timeout = val;

	ret = sbp_update_unit_directory(tport);
	if (ret < 0)
		return ret;

	return count;
}

static ssize_t sbp_tpg_attrib_show_max_reconnect_timeout(
		struct se_portal_group *se_tpg,
		char *page)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;
	return sprintf(page, "%d\n", tport->max_reconnect_timeout);
}

static ssize_t sbp_tpg_attrib_store_max_reconnect_timeout(
		struct se_portal_group *se_tpg,
		const char *page,
		size_t count)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;
	unsigned long val;
	int ret;

	if (kstrtoul(page, 0, &val) < 0)
		return -EINVAL;
	if ((val < 1) || (val > 32767))
		return -EINVAL;

	if (tport->max_reconnect_timeout == val)
		return count;

	tport->max_reconnect_timeout = val;

	ret = sbp_update_unit_directory(tport);
	if (ret < 0)
		return ret;

	return count;
}

static ssize_t sbp_tpg_attrib_show_max_logins_per_lun(
		struct se_portal_group *se_tpg,
		char *page)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;
	return sprintf(page, "%d\n", tport->max_logins_per_lun);
}

static ssize_t sbp_tpg_attrib_store_max_logins_per_lun(
		struct se_portal_group *se_tpg,
		const char *page,
		size_t count)
{
	struct sbp_tpg *tpg = container_of(se_tpg, struct sbp_tpg, se_tpg);
	struct sbp_tport *tport = tpg->tport;
	unsigned long val;

	if (kstrtoul(page, 0, &val) < 0)
		return -EINVAL;
	if ((val < 1) || (val > 127))
		return -EINVAL;

	/* XXX: also check against current count? */

	tport->max_logins_per_lun = val;

	return count;
}

TF_TPG_ATTRIB_ATTR(sbp, mgt_orb_timeout, S_IRUGO | S_IWUSR);
TF_TPG_ATTRIB_ATTR(sbp, max_reconnect_timeout, S_IRUGO | S_IWUSR);
TF_TPG_ATTRIB_ATTR(sbp, max_logins_per_lun, S_IRUGO | S_IWUSR);

static struct configfs_attribute *sbp_tpg_attrib_attrs[] = {
	&sbp_tpg_attrib_mgt_orb_timeout.attr,
	&sbp_tpg_attrib_max_reconnect_timeout.attr,
	&sbp_tpg_attrib_max_logins_per_lun.attr,
	NULL,
};

static struct target_core_fabric_ops sbp_ops = {
	.get_fabric_name		= sbp_get_fabric_name,
	.get_fabric_proto_ident		= sbp_get_fabric_proto_ident,
	.tpg_get_wwn			= sbp_get_fabric_wwn,
	.tpg_get_tag			= sbp_get_tag,
	.tpg_get_default_depth		= sbp_get_default_depth,
	.tpg_get_pr_transport_id	= sbp_get_pr_transport_id,
	.tpg_get_pr_transport_id_len	= sbp_get_pr_transport_id_len,
	.tpg_parse_pr_out_transport_id	= sbp_parse_pr_out_transport_id,
	.tpg_check_demo_mode		= sbp_check_true,
	.tpg_check_demo_mode_cache	= sbp_check_true,
	.tpg_check_demo_mode_write_protect = sbp_check_false,
	.tpg_check_prod_mode_write_protect = sbp_check_false,
	.tpg_alloc_fabric_acl		= sbp_alloc_fabric_acl,
	.tpg_release_fabric_acl		= sbp_release_fabric_acl,
	.tpg_get_inst_index		= sbp_tpg_get_inst_index,
	.release_cmd			= sbp_release_cmd,
	.shutdown_session		= sbp_shutdown_session,
	.close_session			= sbp_close_session,
	.sess_get_index			= sbp_sess_get_index,
	.write_pending			= sbp_write_pending,
	.write_pending_status		= sbp_write_pending_status,
	.set_default_node_attributes	= sbp_set_default_node_attrs,
	.get_task_tag			= sbp_get_task_tag,
	.get_cmd_state			= sbp_get_cmd_state,
	.queue_data_in			= sbp_queue_data_in,
	.queue_status			= sbp_queue_status,
	.queue_tm_rsp			= sbp_queue_tm_rsp,
	.get_fabric_sense_len		= sbp_get_fabric_sense_len,
	.set_fabric_sense_len		= sbp_set_fabric_sense_len,
	.check_stop_free		= sbp_check_stop_free,

	.fabric_make_wwn		= sbp_make_tport,
	.fabric_drop_wwn		= sbp_drop_tport,
	.fabric_make_tpg		= sbp_make_tpg,
	.fabric_drop_tpg		= sbp_drop_tpg,
	.fabric_post_link		= sbp_post_link_lun,
	.fabric_pre_unlink		= sbp_pre_unlink_lun,
	.fabric_make_np			= NULL,
	.fabric_drop_np			= NULL,
	.fabric_make_nodeacl		= sbp_make_nodeacl,
	.fabric_drop_nodeacl		= sbp_drop_nodeacl,
};

static int sbp_register_configfs(void)
{
	struct target_fabric_configfs *fabric;
	int ret;

	fabric = target_fabric_configfs_init(THIS_MODULE, "sbp");
	if (!fabric) {
		pr_err("target_fabric_configfs_init() failed\n");
		return -ENOMEM;
	}

	fabric->tf_ops = sbp_ops;

	/*
	 * Setup default attribute lists for various fabric->tf_cit_tmpl
	 */
	TF_CIT_TMPL(fabric)->tfc_wwn_cit.ct_attrs = sbp_wwn_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_base_cit.ct_attrs = sbp_tpg_base_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_attrib_cit.ct_attrs = sbp_tpg_attrib_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_param_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_np_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_auth_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_param_cit.ct_attrs = NULL;

	ret = target_fabric_configfs_register(fabric);
	if (ret < 0) {
		pr_err("target_fabric_configfs_register() failed for SBP\n");
		return ret;
	}

	sbp_fabric_configfs = fabric;

	return 0;
};

static void sbp_deregister_configfs(void)
{
	if (!sbp_fabric_configfs)
		return;

	target_fabric_configfs_deregister(sbp_fabric_configfs);
	sbp_fabric_configfs = NULL;
};

static int __init sbp_init(void)
{
	int ret;

	ret = sbp_register_configfs();
	if (ret < 0)
		return ret;

	return 0;
};

static void sbp_exit(void)
{
	sbp_deregister_configfs();
};

MODULE_DESCRIPTION("FireWire SBP fabric driver");
MODULE_LICENSE("GPL");
module_init(sbp_init);
module_exit(sbp_exit);
