struct vhost_scsi {
	atomic_t vhost_ref_cnt;
	struct tcm_vhost_tpg *vs_tpg;
	struct vhost_dev dev;
	struct vhost_virtqueue cmd_vq;

	struct vhost_work vs_completion_work; /* cmd completion work item */
	struct list_head vs_completion_list;  /* cmd completion queue */
	spinlock_t vs_completion_lock;        /* protects vs_completion_list */
};

extern int __init vhost_scsi_register(void);
extern int vhost_scsi_deregister(void);
extern void vhost_scsi_complete_cmd(struct tcm_vhost_cmd *tv_cmd);
