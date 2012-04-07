#ifndef __TARGET_USB_GADGET_H__
#define __TARGET_USB_GADGET_H__

#include <linux/kref.h>
/* #include <linux/usb/uas.h> */
#include <linux/usb/composite.h>
#include <linux/usb/storage.h>
#include <scsi/scsi.h>
#include <target/target_core_base.h>
#include <target/target_core_fabric.h>


#include "remove.h"

#define USBG_NAMELEN 32

#define fuas_to_gadget(f)	(f->function.config->cdev->gadget)
#define UASP_SS_EP_COMP_LOG_STREAMS 4
#define UASP_SS_EP_COMP_NUM_STREAMS (1 << UASP_SS_EP_COMP_LOG_STREAMS)

struct usbg_nacl {
	/* Binary World Wide unique Port Name for SAS Initiator port */
	u64 iport_wwpn;
	/* ASCII formatted WWPN for Sas Initiator port */
	char iport_name[USBG_NAMELEN];
	/* Returned by usbg_make_nodeacl() */
	struct se_node_acl se_node_acl;
};

struct tcm_usbg_nexus {
	struct se_session *tvn_se_sess;
};

struct usbg_tpg {
	struct mutex tpg_mutex;
	/* SAS port target portal group tag for TCM */
	u16 tport_tpgt;
	/* Pointer back to usbg_tport */
	struct usbg_tport *tport;
	struct workqueue_struct *workqueue;
	/* Returned by usbg_make_tpg() */
	struct se_portal_group se_tpg;
	u32 gadget_connect;
	struct tcm_usbg_nexus *tpg_nexus;
	atomic_t tpg_port_count;
};

struct usbg_tport {
	/* SCSI protocol the tport is providing */
	u8 tport_proto_id;
	/* Binary World Wide unique Port Name for SAS Target port */
	u64 tport_wwpn;
	/* ASCII formatted WWPN for SAS Target port */
	char tport_name[USBG_NAMELEN];
	/* Returned by usbg_make_tport() */
	struct se_wwn tport_wwn;
};

enum uas_state {
	UASP_SEND_DATA,
	UASP_RECEIVE_DATA,
	UASP_SEND_STATUS,
	UASP_QUEUE_COMMAND,
};

#define USBG_MAX_CMD    64
struct usbg_cmd {
	/* common */
	u8 cmd_buf[USBG_MAX_CMD];
	u32 data_len;
	struct work_struct work;
	int unpacked_lun;
	struct se_cmd se_cmd;
	void *data_buf; /* used if no sg support available */
	struct f_uas *fu;
	struct completion write_complete;
	struct kref ref;

	/* UAS only */
	u16 tag;
	u16 prio_attr;
	struct sense_iu sense_iu;
	enum uas_state state;
	struct uas_stream *stream;

	/* BOT only */
	__le32 bot_tag;
	unsigned int csw_code;
	unsigned is_read:1;

};

struct uas_stream {
	struct usb_request	*req_in;
	struct usb_request	*req_out;
	struct usb_request	*req_status;
};

struct usbg_cdb {
	struct usb_request	*req;
	void			*buf;
};

struct bot_status {
	struct usb_request	*req;
	struct bulk_cs_wrap	csw;
};

struct f_uas {
	struct usbg_tpg		*tpg;
	struct usb_function	function;
	u16			iface;

	u32			flags;
#define USBG_ENABLED		(1 << 0)
#define USBG_IS_UAS		(1 << 1)
#define USBG_USE_STREAMS	(1 << 2)
#define USBG_IS_BOT		(1 << 3)
#define USBG_BOT_CMD_PEND	(1 << 4)

	struct usbg_cdb		cmd;
	struct usb_ep		*ep_in;
	struct usb_ep		*ep_out;

	/* UAS */
	struct usb_ep		*ep_status;
	struct usb_ep		*ep_cmd;
	struct uas_stream	stream[UASP_SS_EP_COMP_NUM_STREAMS];

	/* BOT */
	struct bot_status	bot_status;
	struct usb_request	*bot_req_in;
	struct usb_request	*bot_req_out;
};

extern struct usbg_tpg *the_only_tpg_I_currently_have;

static inline struct f_uas *to_f_uas(struct usb_function *f)
{
	return container_of(f, struct f_uas, function);
}

int usbg_register_configfs(void);
void usbg_deregister_configfs(void);
int usbg_attach(struct usbg_tpg *tpg);
void usbg_detach(struct usbg_tpg *tpg);
int usbg_submit_command(struct f_uas *fu, void *cmdbuf, unsigned int len);
int bot_submit_command(struct f_uas *fu, void *cmdbuf, unsigned int len);
void usbg_cmd_release(struct kref *ref);
void usbg_data_write_cmpl(struct usb_ep *ep, struct usb_request *req);
int usbg_prepare_w_request(struct usbg_cmd *cmd, struct usb_request *req);

static inline void usbg_cleanup_cmd(struct usbg_cmd *cmd)
{
	kref_put(&cmd->ref, usbg_cmd_release);
}

int usbg_bot_setup(struct usb_function *f,
		const struct usb_ctrlrequest *ctrl);
void bot_cleanup_old_alt(struct f_uas *fu);
void bot_set_alt(struct f_uas *fu);
void uasp_set_alt(struct f_uas *fu);
void uasp_cleanup_old_alt(struct f_uas *fu);
int usbg_send_status_response(struct se_cmd *se_cmd);
int bot_send_status_response(struct usbg_cmd *cmd);
int uasp_send_status_response(struct usbg_cmd *cmd);
int usbg_send_write_request(struct se_cmd *se_cmd);
int bot_send_write_request(struct usbg_cmd *cmd);
int uasp_send_write_request(struct usbg_cmd *cmd);
int usbg_send_read_response(struct se_cmd *se_cmd);
int bot_send_read_response(struct usbg_cmd *cmd);
int uasp_send_read_response(struct usbg_cmd *cmd);

int usbg_check_true(struct se_portal_group *);
int usbg_check_false(struct se_portal_group *);
char *usbg_get_fabric_name(void);
u8 usbg_get_fabric_proto_ident(struct se_portal_group *);
char *usbg_get_fabric_wwn(struct se_portal_group *);
u16 usbg_get_tag(struct se_portal_group *);
u32 usbg_get_default_depth(struct se_portal_group *);
u32 usbg_get_pr_transport_id(struct se_portal_group *, struct se_node_acl *,
		struct t10_pr_registration *, int *, unsigned char *);
u32 usbg_get_pr_transport_id_len(struct se_portal_group *,
		struct se_node_acl *, struct t10_pr_registration *, int *);
char *usbg_parse_pr_out_transport_id(struct se_portal_group *,
		const char *, u32 *, char **);
struct se_node_acl *usbg_alloc_fabric_acl(struct se_portal_group *);
void usbg_release_fabric_acl(struct se_portal_group *,
		struct se_node_acl *);
u32 usbg_tpg_get_inst_index(struct se_portal_group *);
int usbg_new_cmd(struct se_cmd *se_cmd);
int usbg_cmd_queue_supported(struct se_cmd *se_cmd);
void usbg_release_cmd(struct se_cmd *);
int usbg_shutdown_session(struct se_session *);
void usbg_close_session(struct se_session *);
u32 usbg_sess_get_index(struct se_session *);
int usbg_write_pending(struct se_cmd *);
int usbg_write_pending_status(struct se_cmd *);
void usbg_set_default_node_attrs(struct se_node_acl *);
u32 usbg_get_task_tag(struct se_cmd *);
int usbg_get_cmd_state(struct se_cmd *);
int usbg_queue_tm_rsp(struct se_cmd *);
u16 usbg_set_fabric_sense_len(struct se_cmd *, u32);
u16 usbg_get_fabric_sense_len(void);

#endif
