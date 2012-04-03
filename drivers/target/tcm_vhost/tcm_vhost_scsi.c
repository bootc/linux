/*
 * Virtio SCSI HBA server in host kernel
 *
 * Copyright IBM Corp. 2010
 * Copyright Rising Tide Systems, LLC. 2011
 *
 * Authors:
 *  Stefan Hajnoczi   <stefanha@linux.vnet.ibm.com>
 *  Nicholas A. Bellinger <nab@risingtidesystems.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h> /* TODO vhost.h currently depends on this */
#include <linux/virtio_scsi.h>
#include "../../vhost/vhost.h" /* TODO this is ugly */

#include <scsi/scsi.h>
#include <scsi/scsi_tcq.h>
#include <target/target_core_base.h>
#include <target/target_core_fabric.h>

#include "tcm_vhost_base.h"
#include "tcm_vhost_scsi.h"

/* From tcm_vhost_configfs.c */
/* Global spinlock to protect tcm_vhost TPG list for vhost IOCTL access */
extern struct mutex tcm_vhost_mutex;
extern struct list_head tcm_vhost_list;

static void vhost_scsi_free_cmd(struct tcm_vhost_cmd *tv_cmd)
{
	struct se_cmd *se_cmd = &tv_cmd->tvc_se_cmd;

	/* TODO locking against target/backend threads? */
	transport_generic_free_cmd(se_cmd, 1);

	if (tv_cmd->tvc_sgl_count) {
		u32 i;
		for (i = 0; i < tv_cmd->tvc_sgl_count; i++)
			put_page(sg_page(&tv_cmd->tvc_sgl[i]));
	}

	kfree(tv_cmd);
}

/* Dequeue a command from the completion list */
static struct tcm_vhost_cmd *vhost_scsi_get_cmd_from_completion(struct vhost_scsi *vs)
{
	struct tcm_vhost_cmd *tv_cmd = NULL;

	spin_lock_bh(&vs->vs_completion_lock);
	if (list_empty(&vs->vs_completion_list)) {
		spin_unlock_bh(&vs->vs_completion_lock);
		return NULL;
	}

	list_for_each_entry(tv_cmd, &vs->vs_completion_list,
			    tvc_completion_list) {
		list_del(&tv_cmd->tvc_completion_list);
		break;
	}
	spin_unlock_bh(&vs->vs_completion_lock);
	return tv_cmd;
}

/* Fill in status and signal that we are done processing this command
 *
 * This is scheduled in the vhost work queue so we are called with the owner
 * process mm and can access the vring.
 */
static void vhost_scsi_complete_cmd_work(struct vhost_work *work)
{
	struct vhost_scsi *vs = container_of(work, struct vhost_scsi,
	                                     vs_completion_work);
	struct tcm_vhost_cmd *tv_cmd;

	while ((tv_cmd = vhost_scsi_get_cmd_from_completion(vs)) != NULL) {
		struct virtio_scsi_footer v_footer;
		struct se_cmd *se_cmd = &tv_cmd->tvc_se_cmd;
		int ret;

		printk("%s tv_cmd %p resid %u status %#02x\n", __func__,
			tv_cmd, se_cmd->residual_count, se_cmd->scsi_status);

		memset(&v_footer, 0, sizeof(v_footer));
		v_footer.resid = se_cmd->residual_count;
		/* TODO is status_qualifier field needed? */
		v_footer.status = se_cmd->scsi_status;
		v_footer.sense_len = se_cmd->scsi_sense_length;
		memcpy(v_footer.sense, tv_cmd->tvc_sense_buf,
		       v_footer.sense_len);
		ret = copy_to_user(tv_cmd->tvc_footer, &v_footer,
		                   sizeof(v_footer));
		if (likely(ret == 0))
			vhost_add_used(&vs->cmd_vq, tv_cmd->tvc_vq_desc, 0);
		else
			pr_err("Faulted on virtio_scsi_footer\n");

		vhost_scsi_free_cmd(tv_cmd);
	}

	vhost_signal(&vs->dev, &vs->cmd_vq);
}

void vhost_scsi_complete_cmd(struct tcm_vhost_cmd *tv_cmd)
{
	struct vhost_scsi *vs = tv_cmd->tvc_vhost;

	printk("%s tv_cmd %p\n", __func__, tv_cmd);

	spin_lock_bh(&vs->vs_completion_lock);
	list_add_tail(&tv_cmd->tvc_completion_list, &vs->vs_completion_list);
	spin_unlock_bh(&vs->vs_completion_lock);

	vhost_work_queue(&vs->dev, &vs->vs_completion_work);
}

static struct tcm_vhost_cmd *vhost_scsi_allocate_cmd(
	struct tcm_vhost_tpg *tv_tpg,
	struct virtio_scsi_cmd_header *v_header,
	u32 exp_data_len,
	int data_direction)
{
	struct tcm_vhost_cmd *tv_cmd;
	struct tcm_vhost_nexus *tv_nexus;
	struct se_portal_group *se_tpg = &tv_tpg->se_tpg;
	struct se_session *se_sess;
	struct se_cmd *se_cmd;
	int sam_task_attr;

	tv_nexus = tv_tpg->tpg_nexus;
	if (!tv_nexus) {
		pr_err("Unable to locate active struct tcm_vhost_nexus\n");
		return ERR_PTR(-EIO);
	}
	se_sess = tv_nexus->tvn_se_sess;

	tv_cmd = kzalloc(sizeof(struct tcm_vhost_cmd), GFP_ATOMIC);
	if (!tv_cmd) {
		pr_err("Unable to allocate struct tcm_vhost_cmd\n");
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&tv_cmd->tvc_completion_list);
	tv_cmd->tvc_tag = v_header->tag;

	se_cmd = &tv_cmd->tvc_se_cmd;
	/*
	 * Locate the SAM Task Attr from virtio_scsi_cmd_header
	 */
	sam_task_attr = v_header->task_attr;
	/*
	 * Initialize struct se_cmd descriptor from target_core_mod infrastructure
	 */
	transport_init_se_cmd(se_cmd, se_tpg->se_tpg_tfo, se_sess, exp_data_len,
				data_direction, sam_task_attr,
				&tv_cmd->tvc_sense_buf[0]);

#if 0	/* FIXME: vhost_scsi_allocate_cmd() BIDI operation */
	if (bidi)
		se_cmd->se_cmd_flags |= SCF_BIDI;
#endif
	/*
	 * From here the rest of the se_cmd will be setup and dispatched
	 * via tcm_vhost_new_cmd_map() from TCM backend thread context
	 * after transport_generic_handle_cdb_map() has been called from
	 * vhost_scsi_handle_vq() below..
	 */
	return tv_cmd;
}

/*
 * Map a user memory range into a scatterlist
 *
 * Returns the number of scatterlist entries used or -errno on error.
 */
static int vhost_scsi_map_to_sgl(struct scatterlist *sgl,
		                 unsigned int sgl_count,
		                 void __user *ptr, size_t len, int write)
{
	struct scatterlist *sg = sgl;
	unsigned int npages = 0;
	int ret;

	while (len > 0) {
		struct page *page;
		unsigned int offset = (uintptr_t)ptr & ~PAGE_MASK;
		unsigned int nbytes = min(PAGE_SIZE - offset, len);

		if (npages == sgl_count) {
			ret = -ENOBUFS;
			goto err;
		}

		ret = get_user_pages_fast((unsigned long)ptr, 1, write, &page);
		BUG_ON(ret == 0); /* we should either get our page or fail */
		if (ret < 0)
			goto err;

		sg_set_page(sg, page, nbytes, offset);
		ptr += nbytes;
		len -= nbytes;
		sg++;
		npages++;
	}
	return npages;

err:
	/* Put pages that we hold */
	for (sg = sgl; sg != &sgl[npages]; sg++)
		put_page(sg_page(sg));
	return ret;
}

static int vhost_scsi_map_iov_to_sgl(struct tcm_vhost_cmd *tv_cmd,
                                     struct iovec *iov, unsigned int niov,
				     int write)
{
	int ret;
	unsigned int i;
	u32 sgl_count;
	struct scatterlist *sg;

	/*
	 * Find out how long sglist needs to be
	 */
	sgl_count = 0;
	for (i = 0; i < niov; i++) {
		sgl_count += (((uintptr_t)iov[i].iov_base + iov[i].iov_len +
		             PAGE_SIZE - 1) >> PAGE_SHIFT) -
		             ((uintptr_t)iov[i].iov_base >> PAGE_SHIFT);
	}
	/* TODO overflow checking */

	sg = kmalloc(sizeof(tv_cmd->tvc_sgl[0]) * sgl_count, GFP_ATOMIC);
	if (!sg)
		return -ENOMEM;
	printk("%s sg %p sgl_count %u is_err %ld\n", __func__,
	       sg, sgl_count, IS_ERR(sg));
	sg_init_table(sg, sgl_count);

	tv_cmd->tvc_sgl = sg;
	tv_cmd->tvc_sgl_count = sgl_count;

	printk("Mapping %u iovecs for %u pages\n", niov, sgl_count);
	for (i = 0; i < niov; i++) {
		ret = vhost_scsi_map_to_sgl(sg, sgl_count, iov[i].iov_base,
		                            iov[i].iov_len, write);
		if (ret < 0) {
			for (i = 0; i < tv_cmd->tvc_sgl_count; i++)
				put_page(sg_page(&tv_cmd->tvc_sgl[i]));
			kfree(tv_cmd->tvc_sgl);
			tv_cmd->tvc_sgl = NULL;
			tv_cmd->tvc_sgl_count = 0;
			return ret;
		}

		sg += ret;
		sgl_count -= ret;
	}
	return 0;
}

static void vhost_scsi_handle_vq(struct vhost_scsi *vs)
{
	struct vhost_virtqueue *vq = &vs->cmd_vq;
	struct virtio_scsi_cmd_header v_header;
	struct tcm_vhost_tpg *tv_tpg;
	struct tcm_vhost_cmd *tv_cmd;
	u32 exp_data_len, data_direction;
	unsigned out, in, i;
	int head, ret;

	/* Must use ioctl VHOST_SCSI_SET_ENDPOINT */
	tv_tpg = vs->vs_tpg;
	if (unlikely(!tv_tpg)) {
		pr_err("%s endpoint not set\n", __func__);
		return;
	}

	mutex_lock(&vq->mutex);
	vhost_disable_notify(&vs->dev, vq);

	for (;;) {
		head = vhost_get_vq_desc(&vs->dev, vq, vq->iov,
					ARRAY_SIZE(vq->iov), &out, &in,
					NULL, NULL);
		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			break;
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&vs->dev, vq))) {
				vhost_disable_notify(&vs->dev, vq);
				continue;
			}
			break;
		}

#warning FIXME: BIDI operation
		if (out == 2 && in == 1) {
			data_direction = DMA_NONE;
		} else if (out == 2 && in > 1) {
			data_direction = DMA_FROM_DEVICE;
		} else if (out > 2 && in == 1) {
			data_direction = DMA_TO_DEVICE;
		} else {
			pr_err("Invalid buffer layout out: %u in: %u\n", out, in);
			break;
		}

		/*
		 * Check for a sane footer buffer so we can report errors to
		 * the guest.
		 */
		if (unlikely(vq->iov[out + in - 1].iov_len !=
					sizeof(struct virtio_scsi_footer))) {
			pr_err("Expecting virtio_scsi_footer, got %zu bytes\n",
					vq->iov[out + in - 1].iov_len);
			break;
		}

		if (unlikely(vq->iov[0].iov_len != sizeof(v_header))) {
			pr_err("Expecting virtio_scsi_cmd_header, got %zu bytes\n",
					vq->iov[0].iov_len);
			break;
		}
		ret = __copy_from_user(&v_header, vq->iov[0].iov_base, sizeof(v_header));
		if (unlikely(ret)) {
			pr_err("Faulted on virtio_scsi_cmd_header\n");
			break;
		}

		exp_data_len = 0;
		for (i = 2; i < out + in - 1; i++) {
			exp_data_len += vq->iov[i].iov_len;
		}

		tv_cmd = vhost_scsi_allocate_cmd(tv_tpg, &v_header,
					exp_data_len, data_direction);
		if (IS_ERR(tv_cmd)) {
			pr_err("vhost_scsi_allocate_cmd failed %ld\n", PTR_ERR(tv_cmd));
			break;
		}

		tv_cmd->tvc_vhost = vs;

		if (unlikely(vq->iov[out + in - 1].iov_len !=
		             sizeof(struct virtio_scsi_footer))) {
			pr_err("Expecting virtio_scsi_footer, "
			       " got %zu bytes\n", vq->iov[out + in - 1].iov_len);
			break;
		}
		tv_cmd->tvc_footer = vq->iov[out + in - 1].iov_base;

		if (unlikely(vq->iov[1].iov_len > TCM_VHOST_MAX_CDB_SIZE)) {
			pr_err("CDB length: %zu exceeds %d\n",
				vq->iov[1].iov_len, TCM_VHOST_MAX_CDB_SIZE);
			/* TODO clean up and free tv_cmd */
			break;
		}
		/*
		 * Copy in the recieved CDB descriptor into tv_cmd->tvc_cdb
		 * that will be used by tcm_vhost_new_cmd_map() and down into
		 * target_setup_cmd_from_cdb()
		 */
		ret = __copy_from_user(tv_cmd->tvc_cdb, vq->iov[1].iov_base,
					vq->iov[1].iov_len);
		if (unlikely(ret)) {
			pr_err("Faulted on CDB\n");
			break; /* TODO should all breaks be continues? */
		}
		/*
		 * Check that the recieved CDB size does not exceeded our
		 * hardcoded max for tcm_vhost
		 */
		/* TODO what if cdb was too small for varlen cdb header? */
		if (unlikely(scsi_command_size(tv_cmd->tvc_cdb) > TCM_VHOST_MAX_CDB_SIZE)) {
			pr_err("Received SCSI CDB with command_size: %d that exceeds"
				" SCSI_MAX_VARLEN_CDB_SIZE: %d\n",
				scsi_command_size(tv_cmd->tvc_cdb), TCM_VHOST_MAX_CDB_SIZE);
			break; /* TODO */
		}

		printk("vhost_scsi got command opcode: %#02x, lun: %#llx\n",
			tv_cmd->tvc_cdb[0], v_header.lun);

		if (data_direction != DMA_NONE) {
			ret = vhost_scsi_map_iov_to_sgl(tv_cmd, &vq->iov[2],
					out + in - 3, data_direction == DMA_TO_DEVICE);
			if (unlikely(ret)) {
				pr_err("Failed to map iov to sgl\n");
				break; /* TODO */
			}
		}

		/*
		 * Save the descriptor from vhost_get_vq_desc() to be used to
		 * complete the virtio-scsi request in TCM callback context via
		 * tcm_vhost_queue_data_in() and tcm_vhost_queue_status()
		 */
		tv_cmd->tvc_vq_desc = head;
		/*
		 * Locate the struct se_lun pointer based on v_header->lun, and
		 * attach it to struct se_cmd
		 *
		 * Note this currently assumes v_header->lun has already been unpacked.
		 */
		if (transport_lookup_cmd_lun(&tv_cmd->tvc_se_cmd, v_header.lun) < 0) {
			pr_err("Failed to look up lun: %#08llx\n", v_header.lun);
			/* NON_EXISTENT_LUN */
			transport_send_check_condition_and_sense(&tv_cmd->tvc_se_cmd,
					tv_cmd->tvc_se_cmd.scsi_sense_reason, 0);
			continue;
		}
		/*
		 * Now queue up the newly allocated se_cmd to be processed
		 * within TCM thread context to finish the setup and dispatched
		 * into a TCM backend struct se_device.
		 */
		transport_generic_handle_cdb_map(&tv_cmd->tvc_se_cmd);
	}

	mutex_unlock(&vq->mutex);
}

static void vhost_scsi_handle_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						poll.work);
	struct vhost_scsi *vs = container_of(vq->dev, struct vhost_scsi, dev);

	vhost_scsi_handle_vq(vs);
}

/*
 * Called from vhost_scsi_ioctl() context to walk the list of available tcm_vhost_tpg
 * with an active struct tcm_vhost_nexus
 */
static int vhost_scsi_set_endpoint(
	struct vhost_scsi *vs,
	struct vhost_vring_target *t)
{
	struct tcm_vhost_tport *tv_tport;
	struct tcm_vhost_tpg *tv_tpg;
	struct vhost_virtqueue *vq = &vs->cmd_vq;

	mutex_lock(&vq->mutex);
	/* Verify that ring has been setup correctly. */
	if (!vhost_vq_access_ok(vq)) {
		mutex_unlock(&vq->mutex);
		return -EFAULT;
	}
	if (vs->vs_tpg) {
		mutex_unlock(&vq->mutex);
		return -EEXIST;
	}
	mutex_unlock(&vq->mutex);

	mutex_lock(&tcm_vhost_mutex);
	list_for_each_entry(tv_tpg, &tcm_vhost_list, tv_tpg_list) {
		mutex_lock(&tv_tpg->tv_tpg_mutex);
		if (!tv_tpg->tpg_nexus) {
			mutex_unlock(&tv_tpg->tv_tpg_mutex);
			continue;
		}
		if (atomic_read(&tv_tpg->tv_tpg_vhost_count)) {
			mutex_unlock(&tv_tpg->tv_tpg_mutex);
			continue;
		}
		tv_tport = tv_tpg->tport;

		if (!strcmp(tv_tport->tport_name, t->vhost_wwpn) &&
		    (tv_tpg->tport_tpgt == t->vhost_tpgt)) {
			atomic_inc(&tv_tpg->tv_tpg_vhost_count);
			smp_mb__after_atomic_inc();
			mutex_unlock(&tv_tpg->tv_tpg_mutex);
			mutex_unlock(&tcm_vhost_mutex);

			mutex_lock(&vq->mutex);
			vs->vs_tpg = tv_tpg;
			atomic_inc(&vs->vhost_ref_cnt);
			smp_mb__after_atomic_inc();
			mutex_unlock(&vq->mutex);
			return 0;
		}
		mutex_unlock(&tv_tpg->tv_tpg_mutex);
	}
	mutex_unlock(&tcm_vhost_mutex);

	return -EINVAL;
}

static int vhost_scsi_clear_endpoint(
	struct vhost_scsi *vs,
	struct vhost_vring_target *t)
{
	struct tcm_vhost_tport *tv_tport;
	struct tcm_vhost_tpg *tv_tpg;
	struct vhost_virtqueue *vq = &vs->cmd_vq;

	mutex_lock(&vq->mutex);
	/* Verify that ring has been setup correctly. */
	if (!vhost_vq_access_ok(vq)) {
		mutex_unlock(&vq->mutex);
		return -EFAULT;
	}
	if (!vs->vs_tpg) {
		mutex_unlock(&vq->mutex);
		return -ENODEV;
	}
	tv_tpg = vs->vs_tpg;
	tv_tport = tv_tpg->tport;

	if (strcmp(tv_tport->tport_name, t->vhost_wwpn) ||
	    (tv_tpg->tport_tpgt != t->vhost_tpgt)) {
		mutex_unlock(&vq->mutex);
		pr_warn("tv_tport->tport_name: %s, tv_tpg->tport_tpgt: %hu"
			" does not match t->vhost_wwpn: %s, t->vhost_tpgt: %hu\n",
			tv_tport->tport_name, tv_tpg->tport_tpgt,
			t->vhost_wwpn, t->vhost_tpgt);
		return -EINVAL;
	}
	vs->vs_tpg = NULL;
	mutex_unlock(&vq->mutex);

	return 0;
}

static int vhost_scsi_open(struct inode *inode, struct file *f)
{
	struct vhost_scsi *s;
	int r;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	vhost_work_init(&s->vs_completion_work, vhost_scsi_complete_cmd_work);
	INIT_LIST_HEAD(&s->vs_completion_list);
	spin_lock_init(&s->vs_completion_lock);

	s->cmd_vq.handle_kick = vhost_scsi_handle_kick;
	r = vhost_dev_init(&s->dev, &s->cmd_vq, 1);
	if (r < 0) {
		kfree(s);
		return r;
	}

	f->private_data = s;
	return 0;
}

static int vhost_scsi_release(struct inode *inode, struct file *f)
{
	struct vhost_scsi *s = f->private_data;

	vhost_dev_cleanup(&s->dev);
	kfree(s);
	return 0;
}

static int vhost_scsi_set_features(struct vhost_scsi *vs, u64 features)
{
	if (features & ~VHOST_FEATURES)
		return -EOPNOTSUPP;

	mutex_lock(&vs->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&vs->dev)) {
		mutex_unlock(&vs->dev.mutex);
		return -EFAULT;
	}
	vs->dev.acked_features = features;
	/* TODO possibly smp_wmb() and flush vqs */
	mutex_unlock(&vs->dev.mutex);
	return 0;
}

static long vhost_scsi_ioctl(struct file *f, unsigned int ioctl,
				unsigned long arg)
{
	struct vhost_scsi *vs = f->private_data;
	struct vhost_vring_target backend;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	int r;

	switch (ioctl) {
	case VHOST_SCSI_SET_ENDPOINT:
		if (copy_from_user(&backend, argp, sizeof backend))
			return -EFAULT;

		return vhost_scsi_set_endpoint(vs, &backend);
	case VHOST_SCSI_CLEAR_ENDPOINT:
		if (copy_from_user(&backend, argp, sizeof backend))
			return -EFAULT;

		return vhost_scsi_clear_endpoint(vs, &backend);
	case VHOST_GET_FEATURES:
		features = VHOST_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, featurep, sizeof features))
			return -EFAULT;
		return vhost_scsi_set_features(vs, features);
	default:
		mutex_lock(&vs->dev.mutex);
		r = vhost_dev_ioctl(&vs->dev, ioctl, arg);
		mutex_unlock(&vs->dev.mutex);
		return r;
	}
}

static const struct file_operations vhost_scsi_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_scsi_release,
	.unlocked_ioctl = vhost_scsi_ioctl,
	/* TODO compat ioctl? */
	.open           = vhost_scsi_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_scsi_misc = {
	MISC_DYNAMIC_MINOR,
	"vhost-scsi",
	&vhost_scsi_fops,
};

int __init vhost_scsi_register(void)
{
	return misc_register(&vhost_scsi_misc);
}

int vhost_scsi_deregister(void)
{
	return misc_deregister(&vhost_scsi_misc);
}
