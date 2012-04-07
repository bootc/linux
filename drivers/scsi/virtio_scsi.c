/*
 * Virtio SCSI HBA driver
 *
 * Copyright IBM Corp. 2010
 *
 * Authors:
 *  Stefan Hajnoczi   <stefanha@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>

#define VIRTIO_SCSI_DEBUG 1

static void dbg(const char *fmt, ...)
{
	if (VIRTIO_SCSI_DEBUG) {
		va_list args;

		va_start(args, fmt);
		vprintk(fmt, args);
		va_end(args);
	}
}

#define VIRTIO_SCSI_MAX_SG 256 /* TODO this should come from the virtqueue */

/* Command queue element */
struct virtio_scsi_cmd {
	struct scsi_cmnd *sc;
	union {
		struct virtio_scsi_cmd_header cmd;
		struct virtio_scsi_tmr_header tmr;
	} header;
	struct virtio_scsi_footer footer;
} ____cacheline_aligned_in_smp;

/* Driver instance state */
struct virtio_scsi {
	/* Protects cmd_vq and sg[] */
	spinlock_t cmd_vq_lock;

	/* Queue for commands and task management requests */
	struct virtqueue *cmd_vq;

	/* For sglist construction when adding commands to the virtqueue */
	struct scatterlist sg[VIRTIO_SCSI_MAX_SG];
};

static struct kmem_cache *virtscsi_cmd_cache;

/**
 * virtscsi_complete_cmd - finish a scsi_cmd and invoke scsi_done
 *
 * Called with cmd_vq_lock held.
 */
static void virtscsi_complete_cmd(struct virtio_scsi_cmd *cmd)
{
	struct scsi_cmnd *sc = cmd->sc;

	dbg("%s cmd %p status %#02x sense_len %u\n", __func__,
		cmd, cmd->footer.status, cmd->footer.sense_len);

	sc->result |= cmd->footer.status;
	set_host_byte(sc, DID_OK);

	memcpy(sc->sense_buffer, cmd->footer.sense,
		cmd->footer.sense_len < SCSI_SENSE_BUFFERSIZE ?
		cmd->footer.sense_len : SCSI_SENSE_BUFFERSIZE);

	kmem_cache_free(virtscsi_cmd_cache, cmd);
	cmd = NULL;

	sc->scsi_done(sc);
}

static void virtscsi_cmd_done(struct virtqueue *vq)
{
	struct Scsi_Host *sh = vq->vdev->priv;
	struct virtio_scsi *vscsi = shost_priv(sh);
	struct virtio_scsi_cmd *cmd;
	unsigned long flags;
	unsigned int len;

	spin_lock_irqsave(&vscsi->cmd_vq_lock, flags);

	do {
		virtqueue_disable_cb(vq);
		while ((cmd = virtqueue_get_buf(vq, &len)) != NULL) {
			virtscsi_complete_cmd(cmd);
		}
	} while (!virtqueue_enable_cb(vq));

	spin_unlock_irqrestore(&vscsi->cmd_vq_lock, flags);
}

/**
 * virtscsi_map_cmd - map a scsi_cmd to a virtqueue scatterlist
 * @vscsi	: virtio_scsi state
 * @sc		: command to be mapped
 * @cmd		: command structure
 * @out_num	: number of read-only elements
 * @in_num	: number of write-only elements
 *
 * Called with cmd_vq_lock held.
 */
static void virtscsi_map_cmd(struct virtio_scsi *vscsi, struct scsi_cmnd *sc,
				struct virtio_scsi_cmd *cmd,
				unsigned int *out_num, unsigned int *in_num)
{
	struct scatterlist *sg = vscsi->sg;
	struct scatterlist *sg_elem;
	unsigned int idx = 0;
	int i;

	*out_num = 1 /* header */ + 1 /* CDB */;
	*in_num = 1 /* footer */;

	/* Header */
	BUG_ON(cmd->header.cmd.header_type != VIRTIO_SCSI_TYPE_CMD);
	sg_set_buf(&sg[idx++], &cmd->header.cmd, sizeof(cmd->header.cmd));

	/* CDB */
	sg_set_buf(&sg[idx++], sc->cmnd, sc->cmd_len);

	/* Data-out/in buffer */
	/* TODO support bidirectional commands with scsi_in()/scsi_out() */
	/* TODO there must be a nicer way */
	BUG_ON(scsi_sg_count(sc) > VIRTIO_SCSI_MAX_SG - 3 /* header, CDB, footer */);
	scsi_for_each_sg(sc, sg_elem, scsi_sg_count(sc), i) {
		sg_set_buf(&sg[idx++], sg_virt(sg_elem), sg_elem->length);
	}

	BUG_ON(sc->sc_data_direction == DMA_BIDIRECTIONAL);
	if (sc->sc_data_direction == DMA_TO_DEVICE)
		*out_num += i;
	else if (sc->sc_data_direction == DMA_FROM_DEVICE)
		*in_num += i;

	/* Footer */
	sg_set_buf(&sg[idx++], &cmd->footer, sizeof(cmd->footer));
}

static int virtscsi_queuecommand(struct Scsi_Host *sh, struct scsi_cmnd *sc)
{
	struct virtio_scsi *vscsi = shost_priv(sh);
	struct virtio_scsi_cmd *cmd;
	unsigned long flags;
	unsigned int out_num, in_num;
	int ret = SCSI_MLQUEUE_HOST_BUSY;

	dbg("%s %d:%d:%d:%d got CDB: %#02x scsi_buf_len: %u\n", __func__,
		sc->device->host->host_no, sc->device->id,
		sc->device->channel, sc->device->lun,
		sc->cmnd[0], scsi_bufflen(sc));

	cmd = kmem_cache_zalloc(virtscsi_cmd_cache, GFP_ATOMIC);
	if (!cmd)
		return SCSI_MLQUEUE_HOST_BUSY;

	cmd->sc = sc; /* TODO hang cmd off sc instead of vice versa? */
	cmd->header.cmd = (struct virtio_scsi_cmd_header){
		.header_type = VIRTIO_SCSI_TYPE_CMD,
		.lun = sc->device->lun, /* TODO shift? */
		.tag = (__u64)cmd,
		.task_attr = 0, /* TODO */
	};

	spin_lock_irqsave(&vscsi->cmd_vq_lock, flags);

	virtscsi_map_cmd(vscsi, sc, cmd, &out_num, &in_num);

	if (virtqueue_add_buf(vscsi->cmd_vq, vscsi->sg,
				out_num, in_num, cmd, GFP_ATOMIC) >= 0) {
		virtqueue_kick(vscsi->cmd_vq); /* TODO is there a way to batch commands? */
		ret = 0;
	}

	spin_unlock_irqrestore(&vscsi->cmd_vq_lock, flags);
	return ret;
}

static struct scsi_host_template virtscsi_host_template = {
	.module = THIS_MODULE,
	.name = "Virtio SCSI HBA",
	.proc_name = "virtio_scsi",
	.queuecommand = virtscsi_queuecommand,
	.this_id = -1,

	/* TODO correct these */
	.can_queue = 1024,
	.sg_tablesize = 256,
	.max_sectors = 1024,
	.dma_boundary = DISABLE_CLUSTERING,
	.cmd_per_lun = 1,
};

static int __devinit virtscsi_probe(struct virtio_device *vdev)
{
	struct Scsi_Host *shost;
	struct virtio_scsi *vscsi;
	int err;

	shost = scsi_host_alloc(&virtscsi_host_template, sizeof(*vscsi));
	if (!shost)
		return -ENOMEM;

	vdev->priv = shost;
	vscsi = shost_priv(shost);

	spin_lock_init(&vscsi->cmd_vq_lock);

	vscsi->cmd_vq = virtio_find_single_vq(vdev, virtscsi_cmd_done, "cmd");
	if (IS_ERR(vscsi->cmd_vq)) {
		err = PTR_ERR(vscsi->cmd_vq);
		goto virtio_find_single_vq_failed;
	}

	/* TODO correct these */
	shost->max_id = 1;
	shost->max_lun = 8;
	shost->max_channel = 0;
	shost->max_cmd_len = 32;

	err = scsi_add_host(shost, &vdev->dev);
	if (err)
		goto scsi_add_host_failed;

	scsi_scan_host(shost);

	return 0;

scsi_add_host_failed:
	vdev->config->del_vqs(vdev);
virtio_find_single_vq_failed:
	scsi_host_put(shost);
	return err;
}

static void __devexit virtscsi_remove(struct virtio_device *vdev)
{
	struct Scsi_Host *shost = vdev->priv;

	scsi_remove_host(shost);

	/* Stop all the virtqueues. */
	vdev->config->reset(vdev);

	vdev->config->del_vqs(vdev);
	scsi_host_put(shost);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SCSI, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_scsi_driver = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtscsi_probe,
	.remove = __devexit_p(virtscsi_remove),
};

static int __init init(void)
{
	virtscsi_cmd_cache = KMEM_CACHE(virtio_scsi_cmd, 0);
	if (!virtscsi_cmd_cache) {
		printk(KERN_ERR "kmem_cache_create() for "
				"virtscsi_cmd_cache failed\n");
		return -ENOMEM;
	}

	return register_virtio_driver(&virtio_scsi_driver);
}

static void __exit fini(void)
{
	unregister_virtio_driver(&virtio_scsi_driver);
	kmem_cache_destroy(virtscsi_cmd_cache);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio SCSI HBA driver");
MODULE_LICENSE("GPL");
