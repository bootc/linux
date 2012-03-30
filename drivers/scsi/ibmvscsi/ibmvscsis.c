/*
 * IBM eServer i/pSeries Virtual SCSI Target Driver
 * Copyright (C) 2003-2005 Dave Boutcher (boutcher@us.ibm.com) IBM Corp.
 *			   Santiago Leon (santil@us.ibm.com) IBM Corp.
 *			   Linda Xie (lxie@us.ibm.com) IBM Corp.
 *
 * Copyright (C) 2005-2011 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2010 Nicholas A. Bellinger <nab@kernel.org>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/utsname.h>
#include <asm/unaligned.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_tcq.h>
#include <scsi/libsrp.h>
#include <generated/utsrelease.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_fabric_configfs.h>
#include <target/target_core_configfs.h>
#include <target/target_core_backend.h>

#include <asm/hvcall.h>
#include <asm/iommu.h>
#include <asm/prom.h>
#include <asm/vio.h>

#include "ibmvscsi.h"
#include "viosrp.h"

#define IBMVSCSIS_VERSION  "v0.1"
#define IBMVSCSIS_NAMELEN 32

#define	INITIAL_SRP_LIMIT	16
#define	DEFAULT_MAX_SECTORS	256

/*
 * Hypervisor calls.
 */
#define h_copy_rdma(l, sa, sb, da, db) \
			plpar_hcall_norets(H_COPY_RDMA, l, sa, sb, da, db)
#define h_send_crq(ua, l, h) \
			plpar_hcall_norets(H_SEND_CRQ, ua, l, h)
#define h_reg_crq(ua, tok, sz)\
			plpar_hcall_norets(H_REG_CRQ, ua, tok, sz);
#define h_free_crq(ua) \
			plpar_hcall_norets(H_FREE_CRQ, ua);

#define GETTARGET(x) ((int)((((u64)(x)) >> 56) & 0x003f))
#define GETBUS(x) ((int)((((u64)(x)) >> 53) & 0x0007))
#define GETLUN(x) ((int)((((u64)(x)) >> 48) & 0x001f))

/*
 * These are fixed for the system and come from the Open Firmware device tree.
 * We just store them here to save getting them every time.
 */
static char system_id[64] = "";
static char partition_name[97] = "UNKNOWN";
static unsigned int partition_number = -1;

static LIST_HEAD(tpg_list);
static DEFINE_SPINLOCK(tpg_lock);

struct ibmvscsis_adapter {
	struct vio_dev *dma_dev;
	struct list_head siblings;

	struct crq_queue crq_queue;

	struct work_struct crq_work;

	unsigned long liobn;
	unsigned long riobn;

	/* todo: remove */
	struct srp_target srpt;

	/* SRP port target portal group tag for TCM */
	unsigned long tport_tpgt;

	/* Returned by ibmvscsis_make_tpg() */
	struct se_portal_group se_tpg;

	struct se_session *se_sess;


	/* SCSI protocol the tport is providing */
	u8 tport_proto_id;
	/* Binary World Wide unique Port Name for SRP Target port */
	u64 tport_wwpn;
	/* ASCII formatted WWPN for SRP Target port */
	char tport_name[IBMVSCSIS_NAMELEN];
	/* Returned by ibmvscsis_make_tport() */
	struct se_wwn tport_wwn;
};

struct ibmvscsis_cmnd {
	/* Used for libsrp processing callbacks */
	struct scsi_cmnd sc;
	/* Used for TCM Core operations */
	struct se_cmd se_cmd;
	/* Sense buffer that will be mapped into outgoing status */
	unsigned char sense_buf[TRANSPORT_SENSE_BUFFER];
};

static int ibmvscsis_check_true(struct se_portal_group *se_tpg)
{
	return 1;
}

static int ibmvscsis_check_false(struct se_portal_group *se_tpg)
{
	return 0;
}

static char *ibmvscsis_get_fabric_name(void)
{
	return "ibmvscsis";
}

static u8 ibmvscsis_get_fabric_proto_ident(struct se_portal_group *se_tpg)
{
	return 4;
}

static char *ibmvscsis_get_fabric_wwn(struct se_portal_group *se_tpg)
{
	struct ibmvscsis_adapter *adapter =
		container_of(se_tpg, struct ibmvscsis_adapter, se_tpg);

	return adapter->tport_name;
}

static u16 ibmvscsis_get_tag(struct se_portal_group *se_tpg)
{
	struct ibmvscsis_adapter *adapter =
		container_of(se_tpg, struct ibmvscsis_adapter, se_tpg);
	return adapter->tport_tpgt;
}

static u32 ibmvscsis_get_default_depth(struct se_portal_group *se_tpg)
{
	return 1;
}

/* we don't care about the transport id since we never use pr. */
static u32 ibmvscsis_get_pr_transport_id(struct se_portal_group *se_tpg,
					 struct se_node_acl *se_nacl,
					 struct t10_pr_registration *pr_reg,
					 int *format_code,
					 unsigned char *buf)
{
	return 24;
}

static u32 ibmvscsis_get_pr_transport_id_len(struct se_portal_group *se_tpg,
					     struct se_node_acl *se_nacl,
					     struct t10_pr_registration *pr_reg,
					     int *format_code)
{
	return 24;
}

static char *ibmvscsis_parse_pr_out_transport_id(struct se_portal_group *se_tpg,
						 const char *buf,
						 u32 *out_tid_len,
						 char **port_nexus_ptr)
{
	return NULL;
}

struct ibmvscsis_nacl {
	/* Binary World Wide unique Port Name for SRP Initiator port */
	u64 iport_wwpn;
	/* ASCII formatted WWPN for Sas Initiator port */
	char iport_name[IBMVSCSIS_NAMELEN];
	/* Returned by ibmvscsis_make_nodeacl() */
	struct se_node_acl se_node_acl;
};

static struct se_node_acl *ibmvscsis_alloc_fabric_acl(struct se_portal_group *se_tpg)
{
	struct ibmvscsis_nacl *nacl;

	nacl = kzalloc(sizeof(struct ibmvscsis_nacl), GFP_KERNEL);
	if (!(nacl)) {
		printk(KERN_ERR "Unable to alocate struct ibmvscsis_nacl\n");
		return NULL;
	}

	return &nacl->se_node_acl;
}

static void ibmvscsis_release_fabric_acl(struct se_portal_group *se_tpg,
					 struct se_node_acl *se_nacl)
{
	struct ibmvscsis_nacl *nacl = container_of(se_nacl,
			struct ibmvscsis_nacl, se_node_acl);
	kfree(nacl);
}

static u32 ibmvscsis_tpg_get_inst_index(struct se_portal_group *se_tpg)
{
	return 1;
}

static void ibmvscsis_release_cmd(struct se_cmd *se_cmd)
{
	struct ibmvscsis_cmnd *cmd =
		container_of(se_cmd, struct ibmvscsis_cmnd, se_cmd);
	kfree(cmd);
	return;
}

static int ibmvscsis_shutdown_session(struct se_session *se_sess)
{
	return 0;
}

static void ibmvscsis_close_session(struct se_session *se_sess)
{
	return;
}

static void ibmvscsis_stop_session(struct se_session *se_sess,
				   int sess_sleep , int conn_sleep)
{
	return;
}

static void ibmvscsis_reset_nexus(struct se_session *se_sess)
{
	return;
}

static int ibmvscsis_sess_logged_in(struct se_session *se_sess)
{
	return 0;
}

static u32 ibmvscsis_sess_get_index(struct se_session *se_sess)
{
	return 0;
}

static int ibmvscsis_write_pending_status(struct se_cmd *se_cmd)
{
	return 0;
}

static void ibmvscsis_set_default_node_attrs(struct se_node_acl *nacl)
{
	return;
}

static u32 ibmvscsis_get_task_tag(struct se_cmd *se_cmd)
{
	return 0;
}

static int ibmvscsis_get_cmd_state(struct se_cmd *se_cmd)
{
	return 0;
}

static int ibmvscsis_queue_tm_rsp(struct se_cmd *se_cmd)
{
	return 0;
}

static u16 ibmvscsis_set_fabric_sense_len(struct se_cmd *se_cmd,
					  u32 sense_length)
{
	return 0;
}

static u16 ibmvscsis_get_fabric_sense_len(void)
{
	return 0;
}

static int ibmvscsis_is_state_remove(struct se_cmd *se_cmd)
{
	return 0;
}

/* Local pointer to allocated TCM configfs fabric module */
static struct target_fabric_configfs *ibmvscsis_fabric_configfs;

static struct se_portal_group *ibmvscsis_make_tpg(struct se_wwn *wwn,
						  struct config_group *group,
						  const char *name)
{
	struct ibmvscsis_adapter *adapter =
		container_of(wwn, struct ibmvscsis_adapter, tport_wwn);
	struct se_node_acl *acl;
	int ret;
	char *dname = (char *)dev_name(&adapter->dma_dev->dev);

	if (strncmp(name, "tpgt_1", 6))
		return ERR_PTR(-EINVAL);

	ret = core_tpg_register(&ibmvscsis_fabric_configfs->tf_ops, wwn,
				&adapter->se_tpg, (void *)adapter,
				TRANSPORT_TPG_TYPE_NORMAL);
	if (ret)
		return ERR_PTR(-ENOMEM);

	adapter->se_sess = transport_init_session();
	if (IS_ERR(adapter->se_sess)) {
		core_tpg_deregister(&adapter->se_tpg);
		return ERR_PTR(-ENOMEM);
	}

	acl = core_tpg_check_initiator_node_acl(&adapter->se_tpg, dname);
	if (!acl) {
		transport_free_session(adapter->se_sess);
		adapter->se_sess = NULL;
		return ERR_PTR(-ENOMEM);
	}
	adapter->se_sess->se_node_acl = acl;

	transport_register_session(&adapter->se_tpg,
				   adapter->se_sess->se_node_acl,
				   adapter->se_sess, adapter);

	return &adapter->se_tpg;
}

static void ibmvscsis_drop_tpg(struct se_portal_group *se_tpg)
{
	struct ibmvscsis_adapter *adapter =
		container_of(se_tpg, struct ibmvscsis_adapter, se_tpg);
	unsigned long flags;


	transport_deregister_session_configfs(adapter->se_sess);
	transport_free_session(adapter->se_sess);
	core_tpg_deregister(se_tpg);

	spin_lock_irqsave(&tpg_lock, flags);
	adapter->se_sess = NULL;
	spin_unlock_irqrestore(&tpg_lock, flags);
}

static struct se_wwn *ibmvscsis_make_tport(struct target_fabric_configfs *tf,
					   struct config_group *group,
					   const char *name)
{
	struct ibmvscsis_adapter *adapter;
	unsigned long tpgt, flags;

	if (strict_strtoul(name, 10, &tpgt))
		return NULL;

	spin_lock_irqsave(&tpg_lock, flags);
	list_for_each_entry(adapter, &tpg_list, siblings) {
		if (tpgt == adapter->tport_tpgt)
			goto found;
	}

	spin_unlock_irqrestore(&tpg_lock, flags);
	return NULL;
found:
	spin_unlock_irqrestore(&tpg_lock, flags);

	return &adapter->tport_wwn;
}

static void ibmvscsis_drop_tport(struct se_wwn *wwn)
{
}

static ssize_t ibmvscsis_wwn_show_attr_version(struct target_fabric_configfs *tf,
					       char *page)
{
	return sprintf(page, "IBMVSCSIS fabric module %s on %s/%s"
		"on "UTS_RELEASE"\n", IBMVSCSIS_VERSION, utsname()->sysname,
		utsname()->machine);
}

TF_WWN_ATTR_RO(ibmvscsis, version);

static struct configfs_attribute *ibmvscsis_wwn_attrs[] = {
	&ibmvscsis_wwn_version.attr,
	NULL,
};

static int ibmvscsis_write_pending(struct se_cmd *se_cmd);
static int ibmvscsis_queue_data_in(struct se_cmd *se_cmd);
static int ibmvscsis_queue_status(struct se_cmd *se_cmd);
static int ibmvscsis_check_stop_free(struct se_cmd *se_cmd);

static struct target_core_fabric_ops ibmvscsis_ops = {
	.get_fabric_name		= ibmvscsis_get_fabric_name,
	.get_fabric_proto_ident		= ibmvscsis_get_fabric_proto_ident,
	.tpg_get_wwn			= ibmvscsis_get_fabric_wwn,
	.tpg_get_tag			= ibmvscsis_get_tag,
	.tpg_get_default_depth		= ibmvscsis_get_default_depth,
	.tpg_get_pr_transport_id	= ibmvscsis_get_pr_transport_id,
	.tpg_get_pr_transport_id_len	= ibmvscsis_get_pr_transport_id_len,
	.tpg_parse_pr_out_transport_id	= ibmvscsis_parse_pr_out_transport_id,
	.tpg_check_demo_mode		= ibmvscsis_check_true,
	.tpg_check_demo_mode_cache	= ibmvscsis_check_true,
	.tpg_check_demo_mode_write_protect = ibmvscsis_check_false,
	.tpg_check_prod_mode_write_protect = ibmvscsis_check_false,
	.tpg_alloc_fabric_acl		= ibmvscsis_alloc_fabric_acl,
	.tpg_release_fabric_acl		= ibmvscsis_release_fabric_acl,
	.tpg_get_inst_index		= ibmvscsis_tpg_get_inst_index,
	.check_stop_free		= ibmvscsis_check_stop_free,
	.release_cmd			= ibmvscsis_release_cmd,
	.shutdown_session		= ibmvscsis_shutdown_session,
	.close_session			= ibmvscsis_close_session,
	.stop_session			= ibmvscsis_stop_session,
	.fall_back_to_erl0		= ibmvscsis_reset_nexus,
	.sess_logged_in			= ibmvscsis_sess_logged_in,
	.sess_get_index			= ibmvscsis_sess_get_index,
	.sess_get_initiator_sid		= NULL,
	.write_pending			= ibmvscsis_write_pending,
	.write_pending_status		= ibmvscsis_write_pending_status,
	.set_default_node_attributes	= ibmvscsis_set_default_node_attrs,
	.get_task_tag			= ibmvscsis_get_task_tag,
	.get_cmd_state			= ibmvscsis_get_cmd_state,
	.queue_data_in			= ibmvscsis_queue_data_in,
	.queue_status			= ibmvscsis_queue_status,
	.queue_tm_rsp			= ibmvscsis_queue_tm_rsp,
	.get_fabric_sense_len		= ibmvscsis_get_fabric_sense_len,
	.set_fabric_sense_len		= ibmvscsis_set_fabric_sense_len,
	.is_state_remove		= ibmvscsis_is_state_remove,
	.fabric_make_wwn		= ibmvscsis_make_tport,
	.fabric_drop_wwn		= ibmvscsis_drop_tport,
	.fabric_make_tpg		= ibmvscsis_make_tpg,
	.fabric_drop_tpg		= ibmvscsis_drop_tpg,
	.fabric_post_link		= NULL,
	.fabric_pre_unlink		= NULL,
	.fabric_make_np			= NULL,
	.fabric_drop_np			= NULL,
	.fabric_make_nodeacl		= NULL,
	.fabric_drop_nodeacl		= NULL,
};

static inline union viosrp_iu *vio_iu(struct iu_entry *iue)
{
	return (union viosrp_iu *)(iue->sbuf->buf);
}

static int send_iu(struct iu_entry *iue, u64 length, u8 format)
{
	struct srp_target *target = iue->target;
	struct ibmvscsis_adapter *adapter = target->ldata;
	long rc, rc1;
	union {
		struct viosrp_crq cooked;
		u64 raw[2];
	} crq;

	/* First copy the SRP */
	rc = h_copy_rdma(length, adapter->liobn, iue->sbuf->dma,
			 adapter->riobn, iue->remote_token);

	if (rc)
		printk(KERN_ERR "Error %ld transferring data\n", rc);

	crq.cooked.valid = 0x80;
	crq.cooked.format = format;
	crq.cooked.reserved = 0x00;
	crq.cooked.timeout = 0x00;
	crq.cooked.IU_length = length;
	crq.cooked.IU_data_ptr = vio_iu(iue)->srp.rsp.tag;

	if (rc == 0)
		crq.cooked.status = 0x99;	/* Just needs to be non-zero */
	else
		crq.cooked.status = 0x00;

	rc1 = h_send_crq(adapter->dma_dev->unit_address, crq.raw[0],
			 crq.raw[1]);
	if (rc1) {
		printk(KERN_ERR "%ld sending response\n", rc1);
		return rc1;
	}

	return rc;
}

#define SRP_RSP_SENSE_DATA_LEN	18

static int send_rsp(struct iu_entry *iue, struct scsi_cmnd *sc,
		    unsigned char status, unsigned char asc)
{
	union viosrp_iu *iu = vio_iu(iue);
	uint64_t tag = iu->srp.rsp.tag;

	/* If the linked bit is on and status is good */
	if (test_bit(V_LINKED, &iue->flags) && (status == NO_SENSE))
		status = 0x10;

	memset(iu, 0, sizeof(struct srp_rsp));
	iu->srp.rsp.opcode = SRP_RSP;
	iu->srp.rsp.req_lim_delta = 1;
	iu->srp.rsp.tag = tag;

	if (test_bit(V_DIOVER, &iue->flags))
		iu->srp.rsp.flags |= SRP_RSP_FLAG_DIOVER;

	iu->srp.rsp.data_in_res_cnt = 0;
	iu->srp.rsp.data_out_res_cnt = 0;

	iu->srp.rsp.flags &= ~SRP_RSP_FLAG_RSPVALID;

	iu->srp.rsp.resp_data_len = 0;
	iu->srp.rsp.status = status;
	if (status) {
		uint8_t *sense = iu->srp.rsp.data;

		if (sc) {
			iu->srp.rsp.flags |= SRP_RSP_FLAG_SNSVALID;
			iu->srp.rsp.sense_data_len = SCSI_SENSE_BUFFERSIZE;
			memcpy(sense, sc->sense_buffer, SCSI_SENSE_BUFFERSIZE);
		} else {
			iu->srp.rsp.status = SAM_STAT_CHECK_CONDITION;
			iu->srp.rsp.flags |= SRP_RSP_FLAG_SNSVALID;
			iu->srp.rsp.sense_data_len = SRP_RSP_SENSE_DATA_LEN;

			/* Valid bit and 'current errors' */
			sense[0] = (0x1 << 7 | 0x70);
			/* Sense key */
			sense[2] = status;
			/* Additional sense length */
			sense[7] = 0xa;	/* 10 bytes */
			/* Additional sense code */
			sense[12] = asc;
		}
	}

	send_iu(iue, sizeof(iu->srp.rsp) + SRP_RSP_SENSE_DATA_LEN,
		VIOSRP_SRP_FORMAT);

	return 0;
}

static int send_adapter_info(struct iu_entry *iue,
			     dma_addr_t remote_buffer, u16 length)
{
	struct srp_target *target = iue->target;
	struct ibmvscsis_adapter *adapter = target->ldata;
	dma_addr_t data_token;
	struct mad_adapter_info_data *info;
	int err;

	info = dma_alloc_coherent(&adapter->dma_dev->dev, sizeof(*info),
				  &data_token, GFP_KERNEL);
	if (!info) {
		printk(KERN_ERR "bad dma_alloc_coherent %p\n", target);
		return 1;
	}

	/* Get remote info */
	err = h_copy_rdma(sizeof(*info), adapter->riobn, remote_buffer,
			  adapter->liobn, data_token);
	if (err == H_SUCCESS) {
		printk(KERN_INFO "Client connect: %s (%d)\n",
		       info->partition_name, info->partition_number);
	}

	memset(info, 0, sizeof(*info));

	strcpy(info->srp_version, "16.a");
	strncpy(info->partition_name, partition_name,
		sizeof(info->partition_name));
	info->partition_number = partition_number;
	info->mad_version = 1;
	info->os_type = 2;
	info->port_max_txu[0] = DEFAULT_MAX_SECTORS << 9;

	/* Send our info to remote */
	err = h_copy_rdma(sizeof(*info), adapter->liobn, data_token,
			  adapter->riobn, remote_buffer);

	dma_free_coherent(&adapter->dma_dev->dev, sizeof(*info), info,
			  data_token);
	if (err != H_SUCCESS) {
		printk(KERN_INFO "Error sending adapter info %d\n", err);
		return 1;
	}

	return 0;
}

static int process_mad_iu(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	struct viosrp_adapter_info *info;
	struct viosrp_host_config *conf;

	switch (iu->mad.empty_iu.common.type) {
	case VIOSRP_EMPTY_IU_TYPE:
		printk(KERN_ERR "%s\n", "Unsupported EMPTY MAD IU");
		break;
	case VIOSRP_ERROR_LOG_TYPE:
		printk(KERN_ERR "%s\n", "Unsupported ERROR LOG MAD IU");
		iu->mad.error_log.common.status = 1;
		send_iu(iue, sizeof(iu->mad.error_log),	VIOSRP_MAD_FORMAT);
		break;
	case VIOSRP_ADAPTER_INFO_TYPE:
		info = &iu->mad.adapter_info;
		info->common.status = send_adapter_info(iue, info->buffer,
							info->common.length);
		send_iu(iue, sizeof(*info), VIOSRP_MAD_FORMAT);
		break;
	case VIOSRP_HOST_CONFIG_TYPE:
		conf = &iu->mad.host_config;
		conf->common.status = 1;
		send_iu(iue, sizeof(*conf), VIOSRP_MAD_FORMAT);
		break;
	default:
		printk(KERN_ERR "Unknown type %u\n", iu->srp.rsp.opcode);
		iu->mad.empty_iu.common.status = VIOSRP_MAD_NOT_SUPPORTED;
		send_iu(iue, sizeof(iu->mad), VIOSRP_MAD_FORMAT);
		break;
	}

	return 1;
}

static void process_login(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	struct srp_login_rsp *rsp = &iu->srp.login_rsp;
	u64 tag = iu->srp.rsp.tag;

	/*
	 * TODO handle case that requested size is wrong and buffer
	 * format is wrong
	 */
	memset(iu, 0, sizeof(struct srp_login_rsp));
	rsp->opcode = SRP_LOGIN_RSP;
	rsp->req_lim_delta = INITIAL_SRP_LIMIT;
	rsp->tag = tag;
	rsp->max_it_iu_len = sizeof(union srp_iu);
	rsp->max_ti_iu_len = sizeof(union srp_iu);
	/* direct and indirect */
	rsp->buf_fmt = SRP_BUF_FORMAT_DIRECT | SRP_BUF_FORMAT_INDIRECT;

	send_iu(iue, sizeof(*rsp), VIOSRP_SRP_FORMAT);
}

static void process_tsk_mgmt(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	uint64_t tag = iu->srp.rsp.tag;
	uint8_t *resp_data = iu->srp.rsp.data;

	memset(iu, 0, sizeof(struct srp_rsp));
	iu->srp.rsp.opcode = SRP_RSP;
	iu->srp.rsp.req_lim_delta = 1;
	iu->srp.rsp.tag = tag;

	iu->srp.rsp.data_in_res_cnt = 0;
	iu->srp.rsp.data_out_res_cnt = 0;

	iu->srp.rsp.flags &= ~SRP_RSP_FLAG_RSPVALID;

	iu->srp.rsp.resp_data_len = 4;
	/* TASK MANAGEMENT FUNCTION NOT SUPPORTED for now */
	resp_data[3] = 4;

	send_iu(iue, sizeof(iu->srp.rsp) + iu->srp.rsp.resp_data_len,
		VIOSRP_SRP_FORMAT);
}

static int process_srp_iu(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	struct srp_target *target = iue->target;
	int done = 1;
	u8 opcode = iu->srp.rsp.opcode;
	unsigned long flags;

	switch (opcode) {
	case SRP_LOGIN_REQ:
		process_login(iue);
		break;
	case SRP_TSK_MGMT:
		process_tsk_mgmt(iue);
		break;
	case SRP_CMD:
		spin_lock_irqsave(&target->lock, flags);
		list_add_tail(&iue->ilist, &target->cmd_queue);
		spin_unlock_irqrestore(&target->lock, flags);
		done = 0;
		break;
	case SRP_LOGIN_RSP:
	case SRP_I_LOGOUT:
	case SRP_T_LOGOUT:
	case SRP_RSP:
	case SRP_CRED_REQ:
	case SRP_CRED_RSP:
	case SRP_AER_REQ:
	case SRP_AER_RSP:
		printk(KERN_ERR "Unsupported type %u\n", opcode);
		break;
	default:
		printk(KERN_ERR "Unknown type %u\n", opcode);
	}

	return done;
}

static void process_iu(struct viosrp_crq *crq,
		       struct ibmvscsis_adapter *adapter)
{
	struct iu_entry *iue;
	long err;
	int done = 1;

	iue = srp_iu_get(&adapter->srpt);
	if (!iue) {
		printk(KERN_ERR "Error getting IU from pool\n");
		return;
	}

	iue->remote_token = crq->IU_data_ptr;

	err = h_copy_rdma(crq->IU_length, adapter->riobn,
			  iue->remote_token, adapter->liobn, iue->sbuf->dma);

	if (err != H_SUCCESS) {
		printk(KERN_ERR "%ld transferring data error %p\n", err, iue);
		goto out;
	}

	if (crq->format == VIOSRP_MAD_FORMAT)
		done = process_mad_iu(iue);
	else
		done = process_srp_iu(iue);
out:
	if (done)
		srp_iu_put(iue);
}

static void process_crq(struct viosrp_crq *crq,
			struct ibmvscsis_adapter *adapter)
{
	switch (crq->valid) {
	case 0xC0:
		/* initialization */
		switch (crq->format) {
		case 0x01:
			h_send_crq(adapter->dma_dev->unit_address,
				   0xC002000000000000, 0);
			break;
		case 0x02:
			break;
		default:
			printk(KERN_ERR "Unknown format %u\n", crq->format);
		}
		break;
	case 0xFF:
		/* transport event */
		break;
	case 0x80:
		/* real payload */
		switch (crq->format) {
		case VIOSRP_SRP_FORMAT:
		case VIOSRP_MAD_FORMAT:
			process_iu(crq, adapter);
			break;
		case VIOSRP_OS400_FORMAT:
		case VIOSRP_AIX_FORMAT:
		case VIOSRP_LINUX_FORMAT:
		case VIOSRP_INLINE_FORMAT:
			printk(KERN_ERR "Unsupported format %u\n", crq->format);
			break;
		default:
			printk(KERN_ERR "Unknown format %u\n", crq->format);
		}
		break;
	default:
		printk(KERN_ERR "unknown message type 0x%02x!?\n", crq->valid);
	}
}

static inline struct viosrp_crq *next_crq(struct crq_queue *queue)
{
	struct viosrp_crq *crq;
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	crq = &queue->msgs[queue->cur];
	if (crq->valid & 0x80) {
		if (++queue->cur == queue->size)
			queue->cur = 0;
	} else
		crq = NULL;
	spin_unlock_irqrestore(&queue->lock, flags);

	return crq;
}

static int tcm_queuecommand(struct ibmvscsis_adapter *adapter,
			    struct ibmvscsis_cmnd *vsc,
			    struct srp_cmd *scmd)
{
	struct se_cmd *se_cmd;
	int attr;
	int data_len;
	int ret;

	switch (scmd->task_attr) {
	case SRP_SIMPLE_TASK:
		attr = MSG_SIMPLE_TAG;
		break;
	case SRP_ORDERED_TASK:
		attr = MSG_ORDERED_TAG;
		break;
	case SRP_HEAD_TASK:
		attr = MSG_HEAD_TAG;
		break;
	default:
		printk(KERN_WARNING "Task attribute %d not supported\n",
		       scmd->task_attr);
		attr = MSG_SIMPLE_TAG;
	}

	data_len = srp_data_length(scmd, srp_cmd_direction(scmd));

	se_cmd = &vsc->se_cmd;

	transport_init_se_cmd(se_cmd,
			      adapter->se_tpg.se_tpg_tfo,
			      adapter->se_sess, data_len,
			      srp_cmd_direction(scmd),
			      attr, vsc->sense_buf);

	ret = transport_lookup_cmd_lun(se_cmd, scmd->lun);
	if (ret) {
		printk(KERN_ERR "invalid lun %u\n", GETLUN(scmd->lun));
		transport_send_check_condition_and_sense(se_cmd,
							 se_cmd->scsi_sense_reason,
							 0);
		return ret;
	}

	/*
	 * Allocate the necessary tasks to complete the received CDB+data
	 */
	ret = transport_generic_allocate_tasks(se_cmd, scmd->cdb);
	if (ret == -ENOMEM) {
		transport_send_check_condition_and_sense(se_cmd,
				TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);
		transport_generic_free_cmd(se_cmd, 0);
		return 0;
	}
	if (ret == -EINVAL) {
		if (se_cmd->se_cmd_flags & SCF_SCSI_RESERVATION_CONFLICT)
			ibmvscsis_queue_status(se_cmd);
		else
			transport_send_check_condition_and_sense(se_cmd,
					se_cmd->scsi_sense_reason, 0);
		transport_generic_free_cmd(se_cmd, 0);
		return 0;
	}

	transport_handle_cdb_direct(se_cmd);
	return 0;
}

static int ibmvscsis_check_stop_free(struct se_cmd *se_cmd)
{
	if (se_cmd->se_tmr_req)
		return 0;
	transport_generic_free_cmd(se_cmd, 0);
	return 1;
}

static u64 scsi_lun_to_int(u64 lun)
{
	if (GETBUS(lun) || GETLUN(lun))
		return ~0UL;
	else
		return GETTARGET(lun);
}

struct inquiry_data {
	u8 qual_type;
	u8 rmb_reserve;
	u8 version;
	u8 aerc_naca_hisup_format;
	u8 addl_len;
	u8 sccs_reserved;
	u8 bque_encserv_vs_multip_mchngr_reserved;
	u8 reladr_reserved_linked_cmdqueue_vs;
	char vendor[8];
	char product[16];
	char revision[4];
	char vendor_specific[20];
	char reserved1[2];
	char version_descriptor[16];
	char reserved2[22];
	char unique[158];
};

static u64 make_lun(unsigned int bus, unsigned int target, unsigned int lun)
{
	u16 result = (0x8000 |
			   ((target & 0x003f) << 8) |
			   ((bus & 0x0007) << 5) |
			   (lun & 0x001f));
	return ((u64) result) << 48;
}

static int ibmvscsis_inquiry(struct ibmvscsis_adapter *adapter,
			      struct srp_cmd *cmd, char *data)
{
	struct se_portal_group *se_tpg = &adapter->se_tpg;
	struct inquiry_data *id = (struct inquiry_data *)data;
	u64 unpacked_lun, lun = cmd->lun;
	u8 *cdb = cmd->cdb;
	int len;

	if (!data)
		printk(KERN_INFO "%s %d: oomu\n", __func__, __LINE__);

	if (((cdb[1] & 0x3) == 0x3) || (!(cdb[1] & 0x3) && cdb[2])) {
		printk(KERN_INFO "%s %d: invalid req\n", __func__, __LINE__);
		return 0;
	}

	if (cdb[1] & 0x3)
		printk(KERN_INFO "%s %d: needs the normal path\n",
		       __func__, __LINE__);
	else {
		id->qual_type = TYPE_DISK;
		id->rmb_reserve = 0x00;
		id->version = 0x84; /* ISO/IE */
		id->aerc_naca_hisup_format = 0x22; /* naca & fmt 0x02 */
		id->addl_len = sizeof(*id) - 4;
		id->bque_encserv_vs_multip_mchngr_reserved = 0x00;
		id->reladr_reserved_linked_cmdqueue_vs = 0x02; /* CMDQ */
		memcpy(id->vendor, "IBM	    ", 8);
		/*
		 * Don't even ask about the next bit.  AIX uses
		 * hardcoded device naming to recognize device types
		 * and their client won't  work unless we use VOPTA and
		 * VDASD.
		 */
		if (id->qual_type == TYPE_ROM)
			memcpy(id->product, "VOPTA blkdev    ", 16);
		else
			memcpy(id->product, "VDASD blkdev    ", 16);

		memcpy(id->revision, "0001", 4);

		snprintf(id->unique, sizeof(id->unique),
			 "IBM-VSCSI-%s-P%d-%x-%d-%d-%d\n",
			 system_id,
			 partition_number,
			 adapter->dma_dev->unit_address,
			 GETBUS(lun),
			 GETTARGET(lun),
			 GETLUN(lun));
	}

	len = min_t(int, sizeof(*id), cdb[4]);

	unpacked_lun = scsi_lun_to_int(cmd->lun);

	spin_lock(&se_tpg->tpg_lun_lock);

	if (unpacked_lun < TRANSPORT_MAX_LUNS_PER_TPG &&
	    se_tpg->tpg_lun_list[unpacked_lun].lun_status ==
	    TRANSPORT_LUN_STATUS_ACTIVE)
		;
	else
		data[0] = TYPE_NO_LUN;

	spin_unlock(&se_tpg->tpg_lun_lock);

	return len;
}

static int ibmvscsis_mode_sense(struct ibmvscsis_adapter *adapter,
				struct srp_cmd *cmd, char *mode)
{
	int bytes = 0;
	struct se_portal_group *se_tpg = &adapter->se_tpg;
	u64 unpacked_lun;
	struct se_lun *lun;
	u32 blocks;

	unpacked_lun = scsi_lun_to_int(cmd->lun);

	spin_lock(&se_tpg->tpg_lun_lock);

	lun = &se_tpg->tpg_lun_list[unpacked_lun];

	blocks = lun->lun_se_dev->transport->get_blocks(lun->lun_se_dev);

	spin_unlock(&se_tpg->tpg_lun_lock);

	switch (cmd->cdb[2]) {
	case 0:
	case 0x3f:
		mode[1] = 0x00;	/* Default medium */
		/* if (iue->req.vd->b.ro) */
		if (0)
			mode[2] = 0x80;	/* device specific  */
		else
			mode[2] = 0x00;	/* device specific  */

		/* note the DPOFUA bit is set to zero! */
		mode[3] = 0x08;	/* block descriptor length */
		*((u32 *) &mode[4]) = blocks - 1;
		*((u32 *) &mode[8]) = 512;
		bytes = mode[0] = 12;	/* length */
		break;

	case 0x08: /* Cache page */
		mode[1] = 0x00;	/* Default medium */
		if (0)
			mode[2] = 0x80;	/* device specific */
		else
			mode[2] = 0x00;	/* device specific */

		/* note the DPOFUA bit is set to zero! */
		mode[3] = 0x08;	/* block descriptor length */
		*((u32 *) &mode[4]) = blocks - 1;
		*((u32 *) &mode[8]) = 512;

		/* Cache page */
		mode[12] = 0x08;    /* page */
		mode[13] = 0x12;    /* page length */
		mode[14] = 0x01;    /* no cache (0x04 for read/write cache) */

		bytes = mode[0] = 12 + mode[13];	/* length */
		break;
	}

	return bytes;
}

static int ibmvscsis_report_luns(struct ibmvscsis_adapter *adapter,
				 struct srp_cmd *cmd, u64 *data)
{
	u64 lun;
	struct se_portal_group *se_tpg = &adapter->se_tpg;
	int i, idx;
	int alen, oalen, nr_luns, rbuflen = 4096;

	alen = get_unaligned_be32(&cmd->cdb[6]);

	alen &= ~(8 - 1);
	oalen = alen;

	if (cmd->lun) {
		nr_luns = 1;
		goto done;
	}

	alen -= 8;
	rbuflen -= 8; /* FIXME */
	idx = 2;
	nr_luns = 1;

	spin_lock(&se_tpg->tpg_lun_lock);
	for (i = 0; i < 255; i++) {
		if (se_tpg->tpg_lun_list[i].lun_status !=
		    TRANSPORT_LUN_STATUS_ACTIVE)
			continue;

		lun = make_lun(0, i & 0x003f, 0);
		data[idx++] = cpu_to_be64(lun);
		alen -= 8;
		if (!alen)
			break;
		rbuflen -= 8;
		if (!rbuflen)
			break;

		nr_luns++;
	}
	spin_unlock(&se_tpg->tpg_lun_lock);
done:
	put_unaligned_be32(nr_luns * 8, data);
	return min(oalen, nr_luns * 8 + 8);
}

static int ibmvscsis_rdma(struct scsi_cmnd *sc, struct scatterlist *sg, int nsg,
			  struct srp_direct_buf *md, int nmd,
			  enum dma_data_direction dir, unsigned int rest)
{
	struct iu_entry *iue = (struct iu_entry *) sc->SCp.ptr;
	struct srp_target *target = iue->target;
	struct ibmvscsis_adapter *adapter = target->ldata;
	struct scatterlist *sgp = sg;
	dma_addr_t token;
	long err;
	unsigned int done = 0;
	int i, sidx, soff;

	sidx = soff = 0;
	token = sg_dma_address(sgp);

	for (i = 0; i < nmd && rest; i++) {
		unsigned int mdone, mlen;

		mlen = min(rest, md[i].len);
		for (mdone = 0; mlen;) {
			int slen = min(sg_dma_len(sgp) - soff, mlen);

			if (dir == DMA_TO_DEVICE)
				err = h_copy_rdma(slen,
						  adapter->riobn,
						  md[i].va + mdone,
						  adapter->liobn,
						  token + soff);
			else
				err = h_copy_rdma(slen,
						  adapter->liobn,
						  token + soff,
						  adapter->riobn,
						  md[i].va + mdone);

			if (err != H_SUCCESS) {
				printk(KERN_ERR "rdma error %d %d %ld\n",
				       dir, slen, err);
				return -EIO;
			}

			mlen -= slen;
			mdone += slen;
			soff += slen;
			done += slen;

			if (soff == sg_dma_len(sgp)) {
				sidx++;
				sgp = sg_next(sgp);
				soff = 0;
				token = sg_dma_address(sgp);

				if (sidx > nsg) {
					printk(KERN_ERR "out of iue %p sgp %p %d %d\n",
						iue, sgp, sidx, nsg);
					return -EIO;
				}
			}
		};

		rest -= mlen;
	}
	return 0;
}

static int ibmvscsis_cmd_done(struct scsi_cmnd *sc)
{
	unsigned long flags;
	struct iu_entry *iue = (struct iu_entry *) sc->SCp.ptr;
	struct srp_target *target = iue->target;
	int err = 0;

	if (scsi_sg_count(sc))
		err = srp_transfer_data(sc, &vio_iu(iue)->srp.cmd,
					ibmvscsis_rdma, 1, 1);

	spin_lock_irqsave(&target->lock, flags);
	list_del(&iue->ilist);
	spin_unlock_irqrestore(&target->lock, flags);

	if (err || sc->result != SAM_STAT_GOOD) {
		printk(KERN_ERR "operation failed %p %d %x\n",
		       iue, sc->result, vio_iu(iue)->srp.cmd.cdb[0]);
		send_rsp(iue, sc, HARDWARE_ERROR, 0x00);
	} else
		send_rsp(iue, sc, NO_SENSE, 0x00);

	/* done(sc); */
	srp_iu_put(iue);
	return 0;
}

struct ibmvscsis_cmd {
	/* Used for libsrp processing callbacks */
	struct scsi_cmnd sc;
	/* Used for TCM Core operations */
	struct se_cmd se_cmd;
	/* Sense buffer that will be mapped into outgoing status */
	unsigned char sense_buf[TRANSPORT_SENSE_BUFFER];
};

static int ibmvscsis_write_pending(struct se_cmd *se_cmd)
{
	struct ibmvscsis_cmnd *cmd = container_of(se_cmd,
			struct ibmvscsis_cmnd, se_cmd);
	struct scsi_cmnd *sc = &cmd->sc;
	struct iu_entry *iue = (struct iu_entry *) sc->SCp.ptr;
	int ret;

	sc->sdb.length = se_cmd->data_length;
	sc->sdb.table.nents = se_cmd->t_data_nents;
	sc->sdb.table.sgl = se_cmd->t_data_sg;

	ret = srp_transfer_data(sc, &vio_iu(iue)->srp.cmd,
				ibmvscsis_rdma, 1, 1);
	if (ret) {
		printk(KERN_ERR "srp_transfer_data() failed: %d\n", ret);
		return -EAGAIN;  /* Signal QUEUE_FULL */
	}
	/*
	 * We now tell TCM to add this WRITE CDB directly into the TCM storage
	 * object execution queue.
	 */
	transport_generic_process_write(se_cmd);
	return 0;
}

static int ibmvscsis_queue_data_in(struct se_cmd *se_cmd)
{
	struct ibmvscsis_cmnd *cmd = container_of(se_cmd,
			struct ibmvscsis_cmnd, se_cmd);
	struct scsi_cmnd *sc = &cmd->sc;
	/*
	 * Check for overflow residual count
	 */
	if (se_cmd->se_cmd_flags & SCF_OVERFLOW_BIT)
		scsi_set_resid(sc, se_cmd->residual_count);

	sc->sdb.length = se_cmd->data_length;
	sc->sdb.table.nents = se_cmd->t_data_nents;
	sc->sdb.table.sgl = se_cmd->t_data_sg;

	/*
	 * This will call srp_transfer_data() and post the response
	 * to VIO via libsrp.
	 */
	ibmvscsis_cmd_done(sc);
	return 0;
}

static int ibmvscsis_queue_status(struct se_cmd *se_cmd)
{
	struct ibmvscsis_cmnd *cmd = container_of(se_cmd,
						  struct ibmvscsis_cmnd, se_cmd);
	struct scsi_cmnd *sc = &cmd->sc;
	/*
	 * Copy any generated SENSE data into sc->sense_buffer and
	 * set the appropiate sc->result to be translated by
	 * ibmvscsis_cmd_done()
	 */
	if (se_cmd->sense_buffer &&
	   ((se_cmd->se_cmd_flags & SCF_TRANSPORT_TASK_SENSE) ||
	    (se_cmd->se_cmd_flags & SCF_EMULATED_TASK_SENSE))) {
		memcpy((void *)sc->sense_buffer, (void *)se_cmd->sense_buffer,
				SCSI_SENSE_BUFFERSIZE);
		sc->result = host_byte(DID_OK) | driver_byte(DRIVER_SENSE) |
				SAM_STAT_CHECK_CONDITION;
	} else
		sc->result = host_byte(DID_OK) | se_cmd->scsi_status;
	/*
	 * Finally post the response to VIO via libsrp.
	 */
	ibmvscsis_cmd_done(sc);
	return 0;
}

static int ibmvscsis_queuecommand(struct ibmvscsis_adapter *adapter,
				  struct iu_entry *iue)
{
	int data_len;
	struct srp_cmd *cmd = iue->sbuf->buf;
	struct scsi_cmnd *sc;
	struct page *pg;
	struct ibmvscsis_cmnd *vsc;

	data_len = srp_data_length(cmd, srp_cmd_direction(cmd));

	vsc = kzalloc(sizeof(*vsc), GFP_KERNEL);
	sc = &vsc->sc;
	sc->sense_buffer = vsc->sense_buf;
	sc->cmnd = cmd->cdb;
	sc->SCp.ptr = (char *)iue;

	switch (cmd->cdb[0]) {
	case INQUIRY:
		sg_alloc_table(&sc->sdb.table, 1, GFP_KERNEL);
		pg = alloc_page(GFP_KERNEL|__GFP_ZERO);
		sc->sdb.length = ibmvscsis_inquiry(adapter, cmd,
						   page_address(pg));
		sg_set_page(sc->sdb.table.sgl, pg, sc->sdb.length, 0);
		ibmvscsis_cmd_done(sc);
		sg_free_table(&sc->sdb.table);
		__free_page(pg);
		kfree(vsc);
		break;
	case REPORT_LUNS:
		sg_alloc_table(&sc->sdb.table, 1, GFP_KERNEL);
		pg = alloc_page(GFP_KERNEL|__GFP_ZERO);
		sc->sdb.length = ibmvscsis_report_luns(adapter, cmd,
						       page_address(pg));
		sg_set_page(sc->sdb.table.sgl, pg, sc->sdb.length, 0);
		ibmvscsis_cmd_done(sc);
		sg_free_table(&sc->sdb.table);
		__free_page(pg);
		kfree(vsc);
		break;
	case MODE_SENSE:
		/* fixme: needs to use tcm */
		sg_alloc_table(&sc->sdb.table, 1, GFP_KERNEL);
		pg = alloc_page(GFP_KERNEL|__GFP_ZERO);
		sc->sdb.length = ibmvscsis_mode_sense(adapter,
						      cmd, page_address(pg));
		sg_set_page(sc->sdb.table.sgl, pg, sc->sdb.length, 0);
		ibmvscsis_cmd_done(sc);
		sg_free_table(&sc->sdb.table);
		__free_page(pg);
		kfree(vsc);
		break;
	default:
		tcm_queuecommand(adapter, vsc, cmd);
		break;
	}

	return 0;
}

static void handle_cmd_queue(struct ibmvscsis_adapter *adapter)
{
	struct srp_target *target = &adapter->srpt;
	struct iu_entry *iue;
	unsigned long flags;
	int err;

retry:
	spin_lock_irqsave(&target->lock, flags);

	list_for_each_entry(iue, &target->cmd_queue, ilist) {
		if (!test_and_set_bit(V_FLYING, &iue->flags)) {
			spin_unlock_irqrestore(&target->lock, flags);
			err = ibmvscsis_queuecommand(adapter, iue);
			if (err) {
				printk(KERN_ERR "cannot queue iue %p %d\n",
				       iue, err);
				srp_iu_put(iue);
			}
			goto retry;
		}
	}

	spin_unlock_irqrestore(&target->lock, flags);
}

static void handle_crq(struct work_struct *work)
{
	struct ibmvscsis_adapter *adapter =
		container_of(work, struct ibmvscsis_adapter, crq_work);
	struct viosrp_crq *crq;
	int done = 0;

	while (!done) {
		while ((crq = next_crq(&adapter->crq_queue)) != NULL) {
			process_crq(crq, adapter);
			crq->valid = 0x00;
		}

		vio_enable_interrupts(adapter->dma_dev);

		crq = next_crq(&adapter->crq_queue);
		if (crq) {
			vio_disable_interrupts(adapter->dma_dev);
			process_crq(crq, adapter);
			crq->valid = 0x00;
		} else
			done = 1;
	}

	handle_cmd_queue(adapter);
}

static irqreturn_t ibmvscsis_interrupt(int dummy, void *data)
{
	struct ibmvscsis_adapter *adapter = data;

	vio_disable_interrupts(adapter->dma_dev);
	schedule_work(&adapter->crq_work);

	return IRQ_HANDLED;
}

static int crq_queue_create(struct crq_queue *queue,
			    struct ibmvscsis_adapter *adapter)
{
	int err;
	struct vio_dev *vdev = adapter->dma_dev;

	queue->msgs = (struct viosrp_crq *)get_zeroed_page(GFP_KERNEL);
	if (!queue->msgs)
		goto malloc_failed;
	queue->size = PAGE_SIZE / sizeof(*queue->msgs);

	queue->msg_token = dma_map_single(&vdev->dev, queue->msgs,
					  queue->size * sizeof(*queue->msgs),
					  DMA_BIDIRECTIONAL);

	if (dma_mapping_error(&vdev->dev, queue->msg_token))
		goto map_failed;

	err = h_reg_crq(vdev->unit_address, queue->msg_token,
			PAGE_SIZE);

	/* If the adapter was left active for some reason (like kexec)
	 * try freeing and re-registering
	 */
	if (err == H_RESOURCE) {
		do {
			err = h_free_crq(vdev->unit_address);
		} while (err == H_BUSY || H_IS_LONG_BUSY(err));

		err = h_reg_crq(vdev->unit_address, queue->msg_token,
				PAGE_SIZE);
	}

	if (err != H_SUCCESS && err != 2) {
		printk(KERN_ERR "Error 0x%x opening virtual adapter\n", err);
		goto reg_crq_failed;
	}

	err = request_irq(vdev->irq, &ibmvscsis_interrupt,
			  IRQF_DISABLED, "ibmvscsis", adapter);
	if (err)
		goto req_irq_failed;

	vio_enable_interrupts(vdev);

	h_send_crq(vdev->unit_address, 0xC001000000000000, 0);

	queue->cur = 0;
	spin_lock_init(&queue->lock);

	return 0;

req_irq_failed:
	do {
		err = h_free_crq(vdev->unit_address);
	} while (err == H_BUSY || H_IS_LONG_BUSY(err));

reg_crq_failed:
	dma_unmap_single(&vdev->dev, queue->msg_token,
			 queue->size * sizeof(*queue->msgs), DMA_BIDIRECTIONAL);
map_failed:
	free_page((unsigned long) queue->msgs);

malloc_failed:
	return -ENOMEM;
}

static void crq_queue_destroy(struct ibmvscsis_adapter *adapter)
{
	struct crq_queue *queue = &adapter->crq_queue;
	int err;

	free_irq(adapter->dma_dev->irq, adapter);
	flush_work_sync(&adapter->crq_work);
	do {
		err = h_free_crq(adapter->dma_dev->unit_address);
	} while (err == H_BUSY || H_IS_LONG_BUSY(err));

	dma_unmap_single(&adapter->dma_dev->dev, queue->msg_token,
			 queue->size * sizeof(*queue->msgs), DMA_BIDIRECTIONAL);

	free_page((unsigned long)queue->msgs);
}

static int ibmvscsis_probe(struct vio_dev *dev, const struct vio_device_id *id)
{
	unsigned int *dma, dma_size;
	unsigned long flags;
	int ret;
	struct ibmvscsis_adapter *adapter;

	adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
	if (!adapter)
		return -ENOMEM;

	adapter->dma_dev = dev;

	dma = (unsigned int *)vio_get_attribute(dev, "ibm,my-dma-window",
						&dma_size);
	if (!dma || dma_size != 40) {
		printk(KERN_ERR "Couldn't get window property %d\n", dma_size);
		kfree(adapter);
		return -EIO;
	}

	adapter->liobn = dma[0];
	adapter->riobn = dma[5];
	ret = strict_strtoul(dev_name(&dev->dev), 10, &adapter->tport_tpgt);

	spin_lock_irqsave(&tpg_lock, flags);
	list_add(&adapter->siblings, &tpg_list);
	spin_unlock_irqrestore(&tpg_lock, flags);

	INIT_WORK(&adapter->crq_work, handle_crq);

	dev_set_drvdata(&dev->dev, adapter);

	ret = srp_target_alloc(&adapter->srpt, &dev->dev, INITIAL_SRP_LIMIT,
			       SRP_MAX_IU_LEN);

	adapter->srpt.ldata = adapter;

	ret = crq_queue_create(&adapter->crq_queue, adapter);

	return 0;
}

static int ibmvscsis_remove(struct vio_dev *dev)
{
	struct ibmvscsis_adapter *adapter = dev_get_drvdata(&dev->dev);
	unsigned long flags;

	spin_lock_irqsave(&tpg_lock, flags);
	list_del(&adapter->siblings);
	spin_unlock_irqrestore(&tpg_lock, flags);

	crq_queue_destroy(adapter);

	srp_target_free(&adapter->srpt);

	kfree(adapter);
	return 0;
}

static struct vio_device_id ibmvscsis_device_table[] __devinitdata = {
	{"v-scsi-host", "IBM,v-scsi-host"},
	{"", ""}
};

MODULE_DEVICE_TABLE(vio, ibmvscsis_device_table);

static struct vio_driver ibmvscsis_driver = {
	.id_table = ibmvscsis_device_table,
	.probe = ibmvscsis_probe,
	.remove = ibmvscsis_remove,
	.driver = {
		.name = "ibmvscsis",
		.owner = THIS_MODULE,
	}
};

static int get_system_info(void)
{
	struct device_node *rootdn;
	const char *id, *model, *name;
	const unsigned int *num;

	rootdn = of_find_node_by_path("/");
	if (!rootdn)
		return -ENOENT;

	model = of_get_property(rootdn, "model", NULL);
	id = of_get_property(rootdn, "system-id", NULL);
	if (model && id)
		snprintf(system_id, sizeof(system_id), "%s-%s", model, id);

	name = of_get_property(rootdn, "ibm,partition-name", NULL);
	if (name)
		strncpy(partition_name, name, sizeof(partition_name));

	num = of_get_property(rootdn, "ibm,partition-no", NULL);
	if (num)
		partition_number = *num;

	of_node_put(rootdn);
	return 0;
}

static int ibmvscsis_register_configfs(void)
{
	struct target_fabric_configfs *fabric;
	int ret;

	printk(KERN_INFO "IBMVSCSIS fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n", IBMVSCSIS_VERSION, utsname()->sysname,
		utsname()->machine);
	/*
	 * Register the top level struct config_item_type with TCM core
	 */
	fabric = target_fabric_configfs_init(THIS_MODULE, "ibmvscsis");
	if (IS_ERR(fabric)) {
		printk(KERN_ERR "target_fabric_configfs_init() failed\n");
		return PTR_ERR(fabric);
	}
	/*
	 * Setup fabric->tf_ops from our local ibmvscsis_ops
	 */
	fabric->tf_ops = ibmvscsis_ops;
	/*
	 * Setup default attribute lists for various fabric->tf_cit_tmpl
	 */
	TF_CIT_TMPL(fabric)->tfc_wwn_cit.ct_attrs = ibmvscsis_wwn_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_base_cit.ct_attrs = NULL;
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
		printk(KERN_ERR "target_fabric_configfs_register() failed"
				" for IBMVSCSIS\n");
		target_fabric_configfs_deregister(fabric);
		return ret;
	}
	/*
	 * Setup our local pointer to *fabric
	 */
	ibmvscsis_fabric_configfs = fabric;
	printk(KERN_INFO "IBMVSCSIS[0] - Set fabric -> ibmvscsis_fabric_configfs\n");
	return 0;
};

static void ibmvscsis_deregister_configfs(void)
{
	if (!(ibmvscsis_fabric_configfs))
		return;

	target_fabric_configfs_deregister(ibmvscsis_fabric_configfs);
	ibmvscsis_fabric_configfs = NULL;
	printk(KERN_INFO "IBMVSCSIS[0] - Cleared ibmvscsis_fabric_configfs\n");
};

static int __init ibmvscsis_init(void)
{
	int ret;

	ret = get_system_info();
	if (ret)
		return ret;

	ret = vio_register_driver(&ibmvscsis_driver);
	if (ret)
		return ret;

	ret = ibmvscsis_register_configfs();
	if (ret < 0)
		return ret;

	return 0;
};

static void ibmvscsis_exit(void)
{
	vio_unregister_driver(&ibmvscsis_driver);
	ibmvscsis_deregister_configfs();
};

MODULE_DESCRIPTION("IBMVSCSIS series fabric driver");
MODULE_AUTHOR("FUJITA Tomonori");
MODULE_LICENSE("GPL");
module_init(ibmvscsis_init);
module_exit(ibmvscsis_exit);
