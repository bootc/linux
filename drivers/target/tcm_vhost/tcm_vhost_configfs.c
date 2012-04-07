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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/configfs.h>
#include <linux/ctype.h>
#include <asm/unaligned.h>
#include <scsi/scsi.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h> /* TODO vhost.h currently depends on this */
#include <linux/virtio_scsi.h>
#include "../../vhost/vhost.h" /* TODO this is ugly */

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_fabric_configfs.h>
#include <target/target_core_configfs.h>
#include <target/configfs_macros.h>

#include "tcm_vhost_base.h"
#include "tcm_vhost_fabric.h"
#include "tcm_vhost_scsi.h"

/* Local pointer to allocated TCM configfs fabric module */
struct target_fabric_configfs *tcm_vhost_fabric_configfs;

/* Global spinlock to protect tcm_vhost TPG list for vhost IOCTL access */
DEFINE_MUTEX(tcm_vhost_mutex);
LIST_HEAD(tcm_vhost_list);

static char *tcm_vhost_dump_proto_id(struct tcm_vhost_tport *tport)
{
	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
		return "SAS";
	case SCSI_PROTOCOL_FCP:
		return "FCP";
	case SCSI_PROTOCOL_ISCSI:
		return "iSCSI";
	default:
		break;
	}

	return "Unknown";
}

static int tcm_vhost_port_link(
	struct se_portal_group *se_tpg,
	struct se_lun *lun)
{
	struct tcm_vhost_tpg *tv_tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);

	atomic_inc(&tv_tpg->tv_tpg_port_count);
	smp_mb__after_atomic_inc();

	return 0;
}

static void tcm_vhost_port_unlink(
	struct se_portal_group *se_tpg,
	struct se_lun *se_lun)
{
	struct tcm_vhost_tpg *tv_tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);

	atomic_dec(&tv_tpg->tv_tpg_port_count);
	smp_mb__after_atomic_dec();
}

static struct se_node_acl *tcm_vhost_make_nodeacl(
	struct se_portal_group *se_tpg,
	struct config_group *group,
	const char *name)
{
	struct se_node_acl *se_nacl, *se_nacl_new;
	struct tcm_vhost_nacl *nacl;
	u64 wwpn = 0;
	u32 nexus_depth;

	/* tcm_vhost_parse_wwn(name, &wwpn, 1) < 0)
		return ERR_PTR(-EINVAL); */
	se_nacl_new = tcm_vhost_alloc_fabric_acl(se_tpg);
	if (!se_nacl_new)
		return ERR_PTR(-ENOMEM);
//#warning FIXME: Hardcoded nexus depth in tcm_vhost_make_nodeacl()
	nexus_depth = 1;
	/*
	 * se_nacl_new may be released by core_tpg_add_initiator_node_acl()
	 * when converting a NodeACL from demo mode -> explict
	 */
	se_nacl = core_tpg_add_initiator_node_acl(se_tpg, se_nacl_new,
				name, nexus_depth);
	if (IS_ERR(se_nacl)) {
		tcm_vhost_release_fabric_acl(se_tpg, se_nacl_new);
		return se_nacl;
	}
	/*
	 * Locate our struct tcm_vhost_nacl and set the FC Nport WWPN
	 */
	nacl = container_of(se_nacl, struct tcm_vhost_nacl, se_node_acl);
	nacl->iport_wwpn = wwpn;
	/* tcm_vhost_format_wwn(&nacl->iport_name[0], TCM_VHOST_NAMELEN, wwpn); */

	return se_nacl;
}

static void tcm_vhost_drop_nodeacl(struct se_node_acl *se_acl)
{
	struct tcm_vhost_nacl *nacl = container_of(se_acl,
				struct tcm_vhost_nacl, se_node_acl);
	core_tpg_del_initiator_node_acl(se_acl->se_tpg, se_acl, 1);
	kfree(nacl);
}

static int tcm_vhost_make_nexus(
	struct tcm_vhost_tpg *tv_tpg,
	const char *name)
{
	struct se_portal_group *se_tpg;
	struct tcm_vhost_nexus *tv_nexus;

	mutex_lock(&tv_tpg->tv_tpg_mutex);
	if (tv_tpg->tpg_nexus) {
		mutex_unlock(&tv_tpg->tv_tpg_mutex);
		pr_debug("tv_tpg->tpg_nexus already exists\n");
		return -EEXIST;
	}
	se_tpg = &tv_tpg->se_tpg;

	tv_nexus = kzalloc(sizeof(struct tcm_vhost_nexus), GFP_KERNEL);
	if (!tv_nexus) {
		mutex_unlock(&tv_tpg->tv_tpg_mutex);
		pr_err("Unable to allocate struct tcm_vhost_nexus\n");
		return -ENOMEM;
	}
	/*
	 *  Initialize the struct se_session pointer
	 */
	tv_nexus->tvn_se_sess = transport_init_session();
	if (IS_ERR(tv_nexus->tvn_se_sess)) {
		mutex_unlock(&tv_tpg->tv_tpg_mutex);
		kfree(tv_nexus);
		return -ENOMEM;
	}
	/*
	 * Since we are running in 'demo mode' this call with generate a
	 * struct se_node_acl for the tcm_vhost struct se_portal_group with
	 * the SCSI Initiator port name of the passed configfs group 'name'.
	 */
	tv_nexus->tvn_se_sess->se_node_acl = core_tpg_check_initiator_node_acl(
				se_tpg, (unsigned char *)name);
	if (!tv_nexus->tvn_se_sess->se_node_acl) {
		mutex_unlock(&tv_tpg->tv_tpg_mutex);
		pr_debug("core_tpg_check_initiator_node_acl() failed"
				" for %s\n", name);
		transport_free_session(tv_nexus->tvn_se_sess);
		kfree(tv_nexus);
		return -ENOMEM;
	}
	/*
	 * Now register the TCM vHost virtual I_T Nexus as active with the
	 * call to __transport_register_session()
	 */
	__transport_register_session(se_tpg, tv_nexus->tvn_se_sess->se_node_acl,
			tv_nexus->tvn_se_sess, tv_nexus);
	tv_tpg->tpg_nexus = tv_nexus;

	mutex_unlock(&tv_tpg->tv_tpg_mutex);
	return 0;
}

static int tcm_vhost_drop_nexus(
	struct tcm_vhost_tpg *tpg)
{
	struct se_session *se_sess;
	struct tcm_vhost_nexus *tv_nexus;

	mutex_lock(&tpg->tv_tpg_mutex);
	tv_nexus = tpg->tpg_nexus;
	if (!tv_nexus) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		return -ENODEV;
	}

	se_sess = tv_nexus->tvn_se_sess;
	if (!se_sess) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		return -ENODEV;
	}

	if (atomic_read(&tpg->tv_tpg_port_count)) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		pr_err("Unable to remove TCM_vHost I_T Nexus with"
			" active TPG port count: %d\n",
			atomic_read(&tpg->tv_tpg_port_count));
		return -EPERM;
	}

	if (atomic_read(&tpg->tv_tpg_vhost_count)) {
		pr_err("Unable to remove TCM_vHost I_T Nexus with"
			" active TPG vhost count: %d\n",
			atomic_read(&tpg->tv_tpg_vhost_count));
		return -EPERM;
	}

	pr_debug("TCM_vHost_ConfigFS: Removing I_T Nexus to emulated"
		" %s Initiator Port: %s\n", tcm_vhost_dump_proto_id(tpg->tport),
		tv_nexus->tvn_se_sess->se_node_acl->initiatorname);
	/*
	 * Release the SCSI I_T Nexus to the emulated vHost Target Port
	 */
	transport_deregister_session(tv_nexus->tvn_se_sess);
	tpg->tpg_nexus = NULL;
	mutex_unlock(&tpg->tv_tpg_mutex);

	kfree(tv_nexus);
	return 0;
}

static ssize_t tcm_vhost_tpg_show_nexus(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct tcm_vhost_tpg *tv_tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);
	struct tcm_vhost_nexus *tv_nexus;
	ssize_t ret;

	mutex_lock(&tv_tpg->tv_tpg_mutex);
	tv_nexus = tv_tpg->tpg_nexus;
	if (!tv_nexus) {
		mutex_unlock(&tv_tpg->tv_tpg_mutex);
		return -ENODEV;
	}
	ret = snprintf(page, PAGE_SIZE, "%s\n",
			tv_nexus->tvn_se_sess->se_node_acl->initiatorname);
	mutex_unlock(&tv_tpg->tv_tpg_mutex);

	return ret;
}

static ssize_t tcm_vhost_tpg_store_nexus(
	struct se_portal_group *se_tpg,
	const char *page,
	size_t count)
{
	struct tcm_vhost_tpg *tv_tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);
	struct tcm_vhost_tport *tport_wwn = tv_tpg->tport;
	unsigned char i_port[TCM_VHOST_NAMELEN], *ptr, *port_ptr;
	int ret;
	/*
	 * Shutdown the active I_T nexus if 'NULL' is passed..
	 */
	if (!strncmp(page, "NULL", 4)) {
		ret = tcm_vhost_drop_nexus(tv_tpg);
		return (!ret) ? count : ret;
	}
	/*
	 * Otherwise make sure the passed virtual Initiator port WWN matches
	 * the fabric protocol_id set in tcm_vhost_make_tport(), and call
	 * tcm_vhost_make_nexus().
	 */
	if (strlen(page) > TCM_VHOST_NAMELEN) {
		pr_err("Emulated NAA Sas Address: %s, exceeds"
				" max: %d\n", page, TCM_VHOST_NAMELEN);
		return -EINVAL;
	}
	snprintf(&i_port[0], TCM_VHOST_NAMELEN, "%s", page);

	ptr = strstr(i_port, "naa.");
	if (ptr) {
		if (tport_wwn->tport_proto_id != SCSI_PROTOCOL_SAS) {
			pr_err("Passed SAS Initiator Port %s does not"
				" match target port protoid: %s\n", i_port,
				tcm_vhost_dump_proto_id(tport_wwn));
			return -EINVAL;
		}
		port_ptr = &i_port[0];
		goto check_newline;
	}
	ptr = strstr(i_port, "fc.");
	if (ptr) {
		if (tport_wwn->tport_proto_id != SCSI_PROTOCOL_FCP) {
			pr_err("Passed FCP Initiator Port %s does not"
				" match target port protoid: %s\n", i_port,
				tcm_vhost_dump_proto_id(tport_wwn));
			return -EINVAL;
		}
		port_ptr = &i_port[3]; /* Skip over "fc." */
		goto check_newline;
	}
	ptr = strstr(i_port, "iqn.");
	if (ptr) {
		if (tport_wwn->tport_proto_id != SCSI_PROTOCOL_ISCSI) {
			pr_err("Passed iSCSI Initiator Port %s does not"
				" match target port protoid: %s\n", i_port,
				tcm_vhost_dump_proto_id(tport_wwn));
			return -EINVAL;
		}
		port_ptr = &i_port[0];
		goto check_newline;
	}
	pr_err("Unable to locate prefix for emulated Initiator Port:"
			" %s\n", i_port);
	return -EINVAL;
	/*
	 * Clear any trailing newline for the NAA WWN
	 */
check_newline:
	if (i_port[strlen(i_port)-1] == '\n')
		i_port[strlen(i_port)-1] = '\0';

	ret = tcm_vhost_make_nexus(tv_tpg, port_ptr);
	if (ret < 0)
		return ret;

	return count;
}

TF_TPG_BASE_ATTR(tcm_vhost, nexus, S_IRUGO | S_IWUSR);

static struct configfs_attribute *tcm_vhost_tpg_attrs[] = {
	&tcm_vhost_tpg_nexus.attr,
	NULL,
};

static struct se_portal_group *tcm_vhost_make_tpg(
	struct se_wwn *wwn,
	struct config_group *group,
	const char *name)
{
	struct tcm_vhost_tport*tport = container_of(wwn,
			struct tcm_vhost_tport, tport_wwn);

	struct tcm_vhost_tpg *tpg;
	unsigned long tpgt;
	int ret;

	if (strstr(name, "tpgt_") != name)
		return ERR_PTR(-EINVAL);
	if (strict_strtoul(name + 5, 10, &tpgt) || tpgt > UINT_MAX)
		return ERR_PTR(-EINVAL);

	tpg = kzalloc(sizeof(struct tcm_vhost_tpg), GFP_KERNEL);
	if (!tpg) {
		pr_err("Unable to allocate struct tcm_vhost_tpg");
		return ERR_PTR(-ENOMEM);
	}
	mutex_init(&tpg->tv_tpg_mutex);
	INIT_LIST_HEAD(&tpg->tv_tpg_list);
	tpg->tport = tport;
	tpg->tport_tpgt = tpgt;

	ret = core_tpg_register(&tcm_vhost_fabric_configfs->tf_ops, wwn,
				&tpg->se_tpg, tpg, TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0) {
		kfree(tpg);
		return NULL;
	}
	mutex_lock(&tcm_vhost_mutex);
	list_add_tail(&tpg->tv_tpg_list, &tcm_vhost_list);
	mutex_unlock(&tcm_vhost_mutex);

	return &tpg->se_tpg;
}

static void tcm_vhost_drop_tpg(struct se_portal_group *se_tpg)
{
	struct tcm_vhost_tpg *tpg = container_of(se_tpg,
				struct tcm_vhost_tpg, se_tpg);

	mutex_lock(&tcm_vhost_mutex);
	list_del(&tpg->tv_tpg_list);
	mutex_unlock(&tcm_vhost_mutex);
	/*
	 * Release the virtual I_T Nexus for this vHost TPG
	 */
	tcm_vhost_drop_nexus(tpg);
	/*
	 * Deregister the se_tpg from TCM..
	 */
	core_tpg_deregister(se_tpg);
	kfree(tpg);
}

static struct se_wwn *tcm_vhost_make_tport(
	struct target_fabric_configfs *tf,
	struct config_group *group,
	const char *name)
{
	struct tcm_vhost_tport *tport;
	char *ptr;
	u64 wwpn = 0;
	int off = 0;

	/* if (tcm_vhost_parse_wwn(name, &wwpn, 1) < 0)
		return ERR_PTR(-EINVAL); */

	tport = kzalloc(sizeof(struct tcm_vhost_tport), GFP_KERNEL);
	if (!tport) {
		pr_err("Unable to allocate struct tcm_vhost_tport");
		return ERR_PTR(-ENOMEM);
	}
	tport->tport_wwpn = wwpn;
	/* tcm_vhost_format_wwn(&tport->tport_name[0], TCM_VHOST__NAMELEN, wwpn); */
	/*
	 * Determine the emulated Protocol Identifier and Target Port Name
	 * based on the incoming configfs directory name.
	 */
	ptr = strstr(name, "naa.");
	if (ptr) {
		tport->tport_proto_id = SCSI_PROTOCOL_SAS;
		goto check_len;
	}
	ptr = strstr(name, "fc.");
	if (ptr) {
		tport->tport_proto_id = SCSI_PROTOCOL_FCP;
		off = 3; /* Skip over "fc." */
		goto check_len;
	}
	ptr = strstr(name, "iqn.");
	if (ptr) {
		tport->tport_proto_id = SCSI_PROTOCOL_ISCSI;
		goto check_len;
	}

	pr_err("Unable to locate prefix for emulated Target Port:"
			" %s\n", name);
	return ERR_PTR(-EINVAL);

check_len:
	if (strlen(name) > TCM_VHOST_NAMELEN) {
		pr_err("Emulated %s Address: %s, exceeds"
			" max: %d\n", name, tcm_vhost_dump_proto_id(tport),
			TCM_VHOST_NAMELEN);
		kfree(tport);
		return ERR_PTR(-EINVAL);
	}
	snprintf(&tport->tport_name[0], TCM_VHOST_NAMELEN, "%s", &name[off]);

	pr_debug("TCM_VHost_ConfigFS: Allocated emulated Target"
		" %s Address: %s\n", tcm_vhost_dump_proto_id(tport), name);

	return &tport->tport_wwn;
}

static void tcm_vhost_drop_tport(struct se_wwn *wwn)
{
	struct tcm_vhost_tport *tport = container_of(wwn,
				struct tcm_vhost_tport, tport_wwn);

	pr_debug("TCM_VHost_ConfigFS: Deallocating emulated Target"
		" %s Address: %s\n", tcm_vhost_dump_proto_id(tport),
		tport->tport_name);;

	kfree(tport);
}

static ssize_t tcm_vhost_wwn_show_attr_version(
	struct target_fabric_configfs *tf,
	char *page)
{
	return sprintf(page, "TCM_VHOST fabric module %s on %s/%s"
		"on "UTS_RELEASE"\n", TCM_VHOST_VERSION, utsname()->sysname,
		utsname()->machine);
}

TF_WWN_ATTR_RO(tcm_vhost, version);

static struct configfs_attribute *tcm_vhost_wwn_attrs[] = {
	&tcm_vhost_wwn_version.attr,
	NULL,
};

static struct target_core_fabric_ops tcm_vhost_ops = {
	.get_fabric_name		= tcm_vhost_get_fabric_name,
	.get_fabric_proto_ident		= tcm_vhost_get_fabric_proto_ident,
	.tpg_get_wwn			= tcm_vhost_get_fabric_wwn,
	.tpg_get_tag			= tcm_vhost_get_tag,
	.tpg_get_default_depth		= tcm_vhost_get_default_depth,
	.tpg_get_pr_transport_id	= tcm_vhost_get_pr_transport_id,
	.tpg_get_pr_transport_id_len	= tcm_vhost_get_pr_transport_id_len,
	.tpg_parse_pr_out_transport_id	= tcm_vhost_parse_pr_out_transport_id,
	.tpg_check_demo_mode		= tcm_vhost_check_true,
	.tpg_check_demo_mode_cache	= tcm_vhost_check_true,
	.tpg_check_demo_mode_write_protect = tcm_vhost_check_false,
	.tpg_check_prod_mode_write_protect = tcm_vhost_check_false,
	.tpg_alloc_fabric_acl		= tcm_vhost_alloc_fabric_acl,
	.tpg_release_fabric_acl		= tcm_vhost_release_fabric_acl,
	.tpg_get_inst_index		= tcm_vhost_tpg_get_inst_index,
	.new_cmd_map			= tcm_vhost_new_cmd_map,
	.release_cmd			= tcm_vhost_release_cmd,
	.shutdown_session		= tcm_vhost_shutdown_session,
	.close_session			= tcm_vhost_close_session,
	.sess_get_index			= tcm_vhost_sess_get_index,
	.sess_get_initiator_sid		= NULL,
	.write_pending			= tcm_vhost_write_pending,
	.write_pending_status		= tcm_vhost_write_pending_status,
	.set_default_node_attributes	= tcm_vhost_set_default_node_attrs,
	.get_task_tag			= tcm_vhost_get_task_tag,
	.get_cmd_state			= tcm_vhost_get_cmd_state,
	.queue_data_in			= tcm_vhost_queue_data_in,
	.queue_status			= tcm_vhost_queue_status,
	.queue_tm_rsp			= tcm_vhost_queue_tm_rsp,
	.get_fabric_sense_len		= tcm_vhost_get_fabric_sense_len,
	.set_fabric_sense_len		= tcm_vhost_set_fabric_sense_len,
	/*
	 * Setup function pointers for generic logic in target_core_fabric_configfs.c
	 */
	.fabric_make_wwn		= tcm_vhost_make_tport,
	.fabric_drop_wwn		= tcm_vhost_drop_tport,
	.fabric_make_tpg		= tcm_vhost_make_tpg,
	.fabric_drop_tpg		= tcm_vhost_drop_tpg,
	.fabric_post_link		= tcm_vhost_port_link,
	.fabric_pre_unlink		= tcm_vhost_port_unlink,
	.fabric_make_np			= NULL,
	.fabric_drop_np			= NULL,
	.fabric_make_nodeacl		= tcm_vhost_make_nodeacl,
	.fabric_drop_nodeacl		= tcm_vhost_drop_nodeacl,
};

static int tcm_vhost_register_configfs(void)
{
	struct target_fabric_configfs *fabric;
	int ret;

	pr_debug("TCM_VHOST fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n",TCM_VHOST_VERSION, utsname()->sysname,
		utsname()->machine);
	/*
	 * Register the top level struct config_item_type with TCM core
	 */
	fabric = target_fabric_configfs_init(THIS_MODULE, "vhost");
	if (IS_ERR(fabric)) {
		pr_err("target_fabric_configfs_init() failed\n");
		return PTR_ERR(fabric);
	}
	/*
	 * Setup fabric->tf_ops from our local tcm_vhost_ops
	 */
	fabric->tf_ops = tcm_vhost_ops;
	/*
	 * Setup default attribute lists for various fabric->tf_cit_tmpl
	 */
	TF_CIT_TMPL(fabric)->tfc_wwn_cit.ct_attrs = tcm_vhost_wwn_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_base_cit.ct_attrs = tcm_vhost_tpg_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_param_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_np_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_auth_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_param_cit.ct_attrs = NULL;
	/*
	 * Register the fabric for use within TCM
	 */
	ret = target_fabric_configfs_register(fabric);
	if (ret < 0) {
		pr_err("target_fabric_configfs_register() failed"
				" for TCM_VHOST\n");
		return ret;
	}
	/*
	 * Setup our local pointer to *fabric
	 */
	tcm_vhost_fabric_configfs = fabric;
	pr_debug("TCM_VHOST[0] - Set fabric -> tcm_vhost_fabric_configfs\n");
	return 0;
};

static void tcm_vhost_deregister_configfs(void)
{
	if (!tcm_vhost_fabric_configfs)
		return;

	target_fabric_configfs_deregister(tcm_vhost_fabric_configfs);
	tcm_vhost_fabric_configfs = NULL;
	pr_debug("TCM_VHOST[0] - Cleared tcm_vhost_fabric_configfs\n");
};

static int __init tcm_vhost_init(void)
{
	int ret;

	ret = vhost_scsi_register();
	if (ret < 0)
		return ret;

	ret = tcm_vhost_register_configfs();
	if (ret < 0)
		return ret;

	return 0;
};

static void tcm_vhost_exit(void)
{
	tcm_vhost_deregister_configfs();
	vhost_scsi_deregister();
};

MODULE_DESCRIPTION("TCM_VHOST series fabric driver");
MODULE_LICENSE("GPL");
module_init(tcm_vhost_init);
module_exit(tcm_vhost_exit);
