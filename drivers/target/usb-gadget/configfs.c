 /*
  * Target based USB-Gadget, configfs handling
  * Author: Sebastian Andrzej Siewior <bigeasy at linutronix dot de>
  * License: GPLv2 as published by FSF.
  */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
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

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_fabric_configfs.h>
#include <target/target_core_configfs.h>
#include <target/configfs_macros.h>

#include "usbg.h"

static struct target_fabric_configfs *usbg_fabric_configfs;

static const char *usbg_check_wwn(const char *name)
{
	const char *n;
	unsigned int len;

	n = strstr(name, "naa.");
	if (!n)
		return NULL;
	n += 4;
	len = strlen(n);
	if (len == 0 || len > USBG_NAMELEN - 1)
		return NULL;
	return n;
}

static struct se_node_acl *usbg_make_nodeacl(
	struct se_portal_group *se_tpg,
	struct config_group *group,
	const char *name)
{
	struct se_node_acl *se_nacl, *se_nacl_new;
	struct usbg_nacl *nacl;
	u64 wwpn = 0;
	u32 nexus_depth;
	const char *wnn_name;

	wnn_name = usbg_check_wwn(name);
	if (!wnn_name)
		return ERR_PTR(-EINVAL);
	se_nacl_new = usbg_alloc_fabric_acl(se_tpg);
	if (!(se_nacl_new))
		return ERR_PTR(-ENOMEM);

	nexus_depth = 1;
	/*
	 * se_nacl_new may be released by core_tpg_add_initiator_node_acl()
	 * when converting a NodeACL from demo mode -> explict
	 */
	se_nacl = core_tpg_add_initiator_node_acl(se_tpg, se_nacl_new,
				name, nexus_depth);
	if (IS_ERR(se_nacl)) {
		usbg_release_fabric_acl(se_tpg, se_nacl_new);
		return se_nacl;
	}
	/*
	 * Locate our struct usbg_nacl and set the FC Nport WWPN
	 */
	nacl = container_of(se_nacl, struct usbg_nacl, se_node_acl);
	nacl->iport_wwpn = wwpn;
	snprintf(nacl->iport_name, sizeof(nacl->iport_name), "%s", name);
	return se_nacl;
}

static void usbg_drop_nodeacl(struct se_node_acl *se_acl)
{
	struct usbg_nacl *nacl = container_of(se_acl,
				struct usbg_nacl, se_node_acl);
	core_tpg_del_initiator_node_acl(se_acl->se_tpg, se_acl, 1);
	kfree(nacl);
}

struct usbg_tpg *the_only_tpg_I_currently_have;

static struct se_portal_group *usbg_make_tpg(
	struct se_wwn *wwn,
	struct config_group *group,
	const char *name)
{
	struct usbg_tport *tport = container_of(wwn, struct usbg_tport,
			tport_wwn);
	struct usbg_tpg *tpg;
	unsigned long tpgt;
	int ret;

	if (strstr(name, "tpgt_") != name)
		return ERR_PTR(-EINVAL);
	if (kstrtoul(name + 5, 0, &tpgt) || tpgt > UINT_MAX)
		return ERR_PTR(-EINVAL);
	if (the_only_tpg_I_currently_have) {
		pr_err("Until the gadget framework can't handle multiple\n");
		pr_err("gadgets, you can't do this here.\n");
		return ERR_PTR(-EBUSY);
	}

	tpg = kzalloc(sizeof(struct usbg_tpg), GFP_KERNEL);
	if (!tpg) {
		printk(KERN_ERR "Unable to allocate struct usbg_tpg");
		return ERR_PTR(-ENOMEM);
	}
	mutex_init(&tpg->tpg_mutex);
	atomic_set(&tpg->tpg_port_count, 0);
	tpg->workqueue = alloc_workqueue("tcm_usb_gadget", 0, 1);
	if (!tpg->workqueue) {
		kfree(tpg);
		return NULL;
	}

	tpg->tport = tport;
	tpg->tport_tpgt = tpgt;

	ret = core_tpg_register(&usbg_fabric_configfs->tf_ops, wwn,
				&tpg->se_tpg, tpg,
				TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0) {
		destroy_workqueue(tpg->workqueue);
		kfree(tpg);
		return NULL;
	}
	the_only_tpg_I_currently_have = tpg;
	return &tpg->se_tpg;
}

static void usbg_drop_tpg(struct se_portal_group *se_tpg)
{
	struct usbg_tpg *tpg = container_of(se_tpg,
				struct usbg_tpg, se_tpg);

	core_tpg_deregister(se_tpg);
	destroy_workqueue(tpg->workqueue);
	kfree(tpg);
	the_only_tpg_I_currently_have = NULL;
}

static struct se_wwn *usbg_make_tport(
	struct target_fabric_configfs *tf,
	struct config_group *group,
	const char *name)
{
	struct usbg_tport *tport;
	const char *wnn_name;
	u64 wwpn = 0;

	wnn_name = usbg_check_wwn(name);
	if (!wnn_name)
		return ERR_PTR(-EINVAL);

	tport = kzalloc(sizeof(struct usbg_tport), GFP_KERNEL);
	if (!(tport)) {
		printk(KERN_ERR "Unable to allocate struct usbg_tport");
		return ERR_PTR(-ENOMEM);
	}
	tport->tport_wwpn = wwpn;
	snprintf(tport->tport_name, sizeof(tport->tport_name), wnn_name);
	return &tport->tport_wwn;
}

static void usbg_drop_tport(struct se_wwn *wwn)
{
	struct usbg_tport *tport = container_of(wwn,
				struct usbg_tport, tport_wwn);
	kfree(tport);
}

/*
 * If somebody feels like dropping the version property, go ahead.
 */
static ssize_t usbg_wwn_show_attr_version(
	struct target_fabric_configfs *tf,
	char *page)
{
	return sprintf(page, "usb-gadget fabric module\n");
}
TF_WWN_ATTR_RO(usbg, version);

static struct configfs_attribute *usbg_wwn_attrs[] = {
	&usbg_wwn_version.attr,
	NULL,
};

static ssize_t tcm_usbg_tpg_show_enable(
		struct se_portal_group *se_tpg,
		char *page)
{
	struct usbg_tpg  *tpg = container_of(se_tpg, struct usbg_tpg, se_tpg);

	return snprintf(page, PAGE_SIZE, "%u\n", tpg->gadget_connect);
}

static ssize_t tcm_usbg_tpg_store_enable(
		struct se_portal_group *se_tpg,
		const char *page,
		size_t count)
{
	struct usbg_tpg  *tpg = container_of(se_tpg, struct usbg_tpg, se_tpg);
	unsigned long op;
	ssize_t ret;

	ret = kstrtoul(page, 0, &op);
	if (ret < 0)
		return -EINVAL;
	if (op > 1)
		return -EINVAL;

	if (op && tpg->gadget_connect)
		goto out;
	if (!op && !tpg->gadget_connect)
		goto out;

	if (op) {
		ret = usbg_attach(tpg);
		if (ret)
			goto out;
	} else {
		usbg_detach(tpg);
	}
	tpg->gadget_connect = op;
out:
	return count;
}
TF_TPG_BASE_ATTR(tcm_usbg, enable, S_IRUGO | S_IWUSR);

static ssize_t tcm_usbg_tpg_show_nexus(
		struct se_portal_group *se_tpg,
		char *page)
{
	struct usbg_tpg *tpg = container_of(se_tpg, struct usbg_tpg, se_tpg);
	struct tcm_usbg_nexus *tv_nexus;
	ssize_t ret;

	mutex_lock(&tpg->tpg_mutex);
	tv_nexus = tpg->tpg_nexus;
	if (!tv_nexus) {
		ret = -ENODEV;
		goto out;
	}
	ret = snprintf(page, PAGE_SIZE, "%s\n",
			tv_nexus->tvn_se_sess->se_node_acl->initiatorname);
out:
	mutex_unlock(&tpg->tpg_mutex);
	return ret;
}

static int tcm_usbg_make_nexus(struct usbg_tpg *tpg, char *name)
{
	struct se_portal_group *se_tpg;
	struct tcm_usbg_nexus *tv_nexus;
	int ret;

	mutex_lock(&tpg->tpg_mutex);
	if (tpg->tpg_nexus) {
		ret = -EEXIST;
		pr_debug("tpg->tpg_nexus already exists\n");
		goto err_unlock;
	}
	se_tpg = &tpg->se_tpg;

	ret = -ENOMEM;
	tv_nexus = kzalloc(sizeof(*tv_nexus), GFP_KERNEL);
	if (!tv_nexus) {
		pr_err("Unable to allocate struct tcm_vhost_nexus\n");
		goto err_unlock;
	}
	tv_nexus->tvn_se_sess = transport_init_session();
	if (IS_ERR(tv_nexus->tvn_se_sess))
		goto err_free;

	/*
	 * Since we are running in 'demo mode' this call with generate a
	 * struct se_node_acl for the tcm_vhost struct se_portal_group with
	 * the SCSI Initiator port name of the passed configfs group 'name'.
	 */
	tv_nexus->tvn_se_sess->se_node_acl = core_tpg_check_initiator_node_acl(
			se_tpg, name);
	if (!tv_nexus->tvn_se_sess->se_node_acl) {
		pr_debug("core_tpg_check_initiator_node_acl() failed"
				" for %s\n", name);
		goto err_session;
	}
	/*
	 * Now register the TCM vHost virtual I_T Nexus as active with the
	 * call to __transport_register_session()
	 */
	__transport_register_session(se_tpg, tv_nexus->tvn_se_sess->se_node_acl,
			tv_nexus->tvn_se_sess, tv_nexus);
	tpg->tpg_nexus = tv_nexus;
	mutex_unlock(&tpg->tpg_mutex);
	return 0;

err_session:
	transport_free_session(tv_nexus->tvn_se_sess);
err_free:
	kfree(tv_nexus);
err_unlock:
	mutex_unlock(&tpg->tpg_mutex);
	return ret;
}

static int tcm_usbg_drop_nexus(struct usbg_tpg *tpg)
{
	struct se_session *se_sess;
	struct tcm_usbg_nexus *tv_nexus;
	int ret = -ENODEV;

	mutex_lock(&tpg->tpg_mutex);
	tv_nexus = tpg->tpg_nexus;
	if (!tv_nexus)
		goto out;

	se_sess = tv_nexus->tvn_se_sess;
	if (!se_sess)
		goto out;

	if (atomic_read(&tpg->tpg_port_count)) {
		ret = -EPERM;
		pr_err("Unable to remove Host I_T Nexus with"
				" active TPG port count: %d\n",
				atomic_read(&tpg->tpg_port_count));
		goto out;
	}

	pr_debug("Removing I_T Nexus to Initiator Port: %s\n",
			tv_nexus->tvn_se_sess->se_node_acl->initiatorname);
	/*
	 * Release the SCSI I_T Nexus to the emulated vHost Target Port
	 */
	transport_deregister_session(tv_nexus->tvn_se_sess);
	tpg->tpg_nexus = NULL;

	kfree(tv_nexus);
out:
	mutex_unlock(&tpg->tpg_mutex);
	return 0;
}

static ssize_t tcm_usbg_tpg_store_nexus(
		struct se_portal_group *se_tpg,
		const char *page,
		size_t count)
{
	struct usbg_tpg *tpg = container_of(se_tpg, struct usbg_tpg, se_tpg);
	unsigned char i_port[USBG_NAMELEN], *ptr;
	int ret;

	if (!strncmp(page, "NULL", 4)) {
		ret = tcm_usbg_drop_nexus(tpg);
		return (!ret) ? count : ret;
	}
	if (strlen(page) > USBG_NAMELEN) {
		pr_err("Emulated NAA Sas Address: %s, exceeds"
				" max: %d\n", page, USBG_NAMELEN);
		return -EINVAL;
	}
	snprintf(i_port, USBG_NAMELEN, "%s", page);

	ptr = strstr(i_port, "naa.");
	if (!ptr) {
		pr_err("Missing 'naa.' prefix\n");
		return -EINVAL;
	}

	if (i_port[strlen(i_port) - 1] == '\n')
		i_port[strlen(i_port) - 1] = '\0';

	ret = tcm_usbg_make_nexus(tpg, &i_port[4]);
	if (ret < 0)
		return ret;
	return count;
}
TF_TPG_BASE_ATTR(tcm_usbg, nexus, S_IRUGO | S_IWUSR);

static struct configfs_attribute *usbg_base_attrs[] = {
	&tcm_usbg_tpg_enable.attr,
	&tcm_usbg_tpg_nexus.attr,
	NULL,
};

static int usbg_port_link(struct se_portal_group *se_tpg, struct se_lun *lun)
{
	struct usbg_tpg *tpg = container_of(se_tpg, struct usbg_tpg, se_tpg);

	atomic_inc(&tpg->tpg_port_count);
	smp_mb__after_atomic_inc();
	return 0;
}

static void usbg_port_unlink(struct se_portal_group *se_tpg,
		struct se_lun *se_lun)
{
	struct usbg_tpg *tpg = container_of(se_tpg, struct usbg_tpg, se_tpg);

	atomic_dec(&tpg->tpg_port_count);
	smp_mb__after_atomic_dec();
}

static int usbg_check_stop_free(struct se_cmd *se_cmd)
{
	struct usbg_cmd *cmd = container_of(se_cmd, struct usbg_cmd,
			se_cmd);

	kref_put(&cmd->ref, usbg_cmd_release);
	return 1;
}

static struct target_core_fabric_ops usbg_ops = {
	.get_fabric_name		= usbg_get_fabric_name,
	.get_fabric_proto_ident		= usbg_get_fabric_proto_ident,
	.tpg_get_wwn			= usbg_get_fabric_wwn,
	.tpg_get_tag			= usbg_get_tag,
	.tpg_get_default_depth		= usbg_get_default_depth,
	.tpg_get_pr_transport_id	= usbg_get_pr_transport_id,
	.tpg_get_pr_transport_id_len	= usbg_get_pr_transport_id_len,
	.tpg_parse_pr_out_transport_id	= usbg_parse_pr_out_transport_id,
	.tpg_check_demo_mode		= usbg_check_true,
	.tpg_check_demo_mode_cache	= usbg_check_false,
	.tpg_check_demo_mode_write_protect = usbg_check_false,
	.tpg_check_prod_mode_write_protect = usbg_check_false,
	.tpg_alloc_fabric_acl		= usbg_alloc_fabric_acl,
	.tpg_release_fabric_acl		= usbg_release_fabric_acl,
	.tpg_get_inst_index		= usbg_tpg_get_inst_index,
	.new_cmd_map			= usbg_new_cmd,
	.release_cmd			= usbg_release_cmd,
	.shutdown_session		= usbg_shutdown_session,
	.close_session			= usbg_close_session,
	.sess_get_index			= usbg_sess_get_index,
	.sess_get_initiator_sid		= NULL,
	.write_pending			= usbg_send_write_request,
	.write_pending_status		= usbg_write_pending_status,
	.set_default_node_attributes	= usbg_set_default_node_attrs,
	.get_task_tag			= usbg_get_task_tag,
	.get_cmd_state			= usbg_get_cmd_state,
	.queue_data_in			= usbg_send_read_response,
	.queue_status			= usbg_send_status_response,
	.queue_tm_rsp			= usbg_queue_tm_rsp,
	.get_fabric_sense_len		= usbg_get_fabric_sense_len,
	.set_fabric_sense_len		= usbg_set_fabric_sense_len,
	.check_stop_free		= usbg_check_stop_free,

	.fabric_make_wwn		= usbg_make_tport,
	.fabric_drop_wwn		= usbg_drop_tport,
	.fabric_make_tpg		= usbg_make_tpg,
	.fabric_drop_tpg		= usbg_drop_tpg,
	.fabric_post_link		= usbg_port_link,
	.fabric_pre_unlink		= usbg_port_unlink,
	.fabric_make_np			= NULL,
	.fabric_drop_np			= NULL,
	.fabric_make_nodeacl		= usbg_make_nodeacl,
	.fabric_drop_nodeacl		= usbg_drop_nodeacl,
};

int usbg_register_configfs(void)
{
	struct target_fabric_configfs *fabric;
	int ret;

	fabric = target_fabric_configfs_init(THIS_MODULE, "usb_gadget");
	if (IS_ERR(fabric)) {
		printk(KERN_ERR "target_fabric_configfs_init() failed\n");
		return PTR_ERR(fabric);
	}

	fabric->tf_ops = usbg_ops;
	TF_CIT_TMPL(fabric)->tfc_wwn_cit.ct_attrs = usbg_wwn_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_base_cit.ct_attrs = usbg_base_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_param_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_np_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_auth_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_param_cit.ct_attrs = NULL;
	ret = target_fabric_configfs_register(fabric);
	if (ret < 0) {
		printk(KERN_ERR "target_fabric_configfs_register() failed"
				" for usb-gadget\n");
		return ret;
	}
	usbg_fabric_configfs = fabric;
	return 0;
};

void usbg_deregister_configfs(void)
{
	if (!(usbg_fabric_configfs))
		return;

	target_fabric_configfs_deregister(usbg_fabric_configfs);
	usbg_fabric_configfs = NULL;
};
