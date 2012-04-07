#include <target/target_core_base.h>

#define TCM_QLA2XXX_VERSION	"v0.1"
/* length of ASCII WWPNs including pad */
#define TCM_QLA2XXX_NAMELEN	32
/* lenth of ASCII NPIV 'WWPN+WWNN' including pad */
#define TCM_QLA2XXX_NPIV_NAMELEN 66

#include "qla_target.h"

struct tcm_qla2xxx_nacl {
	/* From libfc struct fc_rport->port_id */
	u32 nport_id;
	/* Binary World Wide unique Node Name for remote FC Initiator Nport */
	u64 nport_wwnn;
	/* ASCII formatted WWPN for FC Initiator Nport */
	char nport_name[TCM_QLA2XXX_NAMELEN];
	/* Pointer to qla_tgt_sess */
	struct qla_tgt_sess *qla_tgt_sess;
	/* Pointer to TCM FC nexus */
	struct se_session *nport_nexus;
	/* Returned by tcm_qla2xxx_make_nodeacl() */
	struct se_node_acl se_node_acl;
};

struct tcm_qla2xxx_tpg_attrib {
	int generate_node_acls;
	int cache_dynamic_acls;
	int demo_mode_write_protect;
	int prod_mode_write_protect;
};

struct tcm_qla2xxx_tpg {
	/* FC lport target portal group tag for TCM */
	u16 lport_tpgt;
	/* Atomic bit to determine TPG active status */
	atomic_t lport_tpg_enabled;
	/* Pointer back to tcm_qla2xxx_lport */
	struct tcm_qla2xxx_lport *lport;
	/* Used by tcm_qla2xxx_tpg_attrib_cit */
	struct tcm_qla2xxx_tpg_attrib tpg_attrib;
	/* Returned by tcm_qla2xxx_make_tpg() */
	struct se_portal_group se_tpg;
};

#define QLA_TPG_ATTRIB(tpg)	(&(tpg)->tpg_attrib)

/*
 * Used for the 24-bit lport->lport_fcport_map;
 */
struct tcm_qla2xxx_fc_al_pa {
	struct se_node_acl *se_nacl;
};

struct tcm_qla2xxx_fc_area {
        struct tcm_qla2xxx_fc_al_pa al_pas[256];
};

struct tcm_qla2xxx_fc_domain {
        struct tcm_qla2xxx_fc_area areas[256];
};

struct tcm_qla2xxx_fc_loopid {
	struct se_node_acl *se_nacl;
};

struct tcm_qla2xxx_lport {
	/* SCSI protocol the lport is providing */
	u8 lport_proto_id;
	/* Binary World Wide unique Port Name for FC Target Lport */
	u64 lport_wwpn;
	/* Binary World Wide unique Port Name for FC NPIV Target Lport */
	u64 lport_npiv_wwpn;
	/* Binary World Wide unique Node Name for FC NPIV Target Lport */
	u64 lport_npiv_wwnn;
	/* ASCII formatted WWPN for FC Target Lport */
	char lport_name[TCM_QLA2XXX_NAMELEN];
	/* ASCII formatted WWPN+WWNN for NPIV FC Target Lport */
	char lport_npiv_name[TCM_QLA2XXX_NPIV_NAMELEN];
	/* vmalloc'ed memory for fc_port pointers in 24-bit FC Port ID space */
	char *lport_fcport_map;
	/* vmalloc-ed memory for fc_port pointers for 16-bit FC loop ID */
	char *lport_loopid_map;
	/* Pointer to struct scsi_qla_host from qla2xxx LLD */
	struct scsi_qla_host *qla_vha;
	/* Pointer to struct scsi_qla_host for NPIV VP from qla2xxx LLD */
	struct scsi_qla_host *qla_npiv_vp;
	/* Pointer to struct qla_tgt pointer */
	struct qla_tgt lport_qla_tgt;
	/* Pointer to struct fc_vport for NPIV vport from libfc */
	struct fc_vport *npiv_vport;
	/* Pointer to TPG=1 for non NPIV mode */
	struct tcm_qla2xxx_tpg *tpg_1;
	/* Returned by tcm_qla2xxx_make_lport() */
	struct se_wwn lport_wwn;
};

extern int tcm_qla2xxx_check_true(struct se_portal_group *);
extern int tcm_qla2xxx_check_false(struct se_portal_group *);
extern ssize_t tcm_qla2xxx_parse_wwn(const char *, u64 *, int);
extern ssize_t tcm_qla2xxx_format_wwn(char *, size_t, u64);
extern char *tcm_qla2xxx_get_fabric_name(void);
extern int tcm_qla2xxx_npiv_parse_wwn(const char *name, size_t, u64 *, u64 *);
extern ssize_t tcm_qla2xxx_npiv_format_wwn(char *, size_t, u64, u64);
extern char *tcm_qla2xxx_npiv_get_fabric_name(void);
extern u8 tcm_qla2xxx_get_fabric_proto_ident(struct se_portal_group *);
extern char *tcm_qla2xxx_get_fabric_wwn(struct se_portal_group *);
extern char *tcm_qla2xxx_npiv_get_fabric_wwn(struct se_portal_group *);
extern u16 tcm_qla2xxx_get_tag(struct se_portal_group *);
extern u32 tcm_qla2xxx_get_default_depth(struct se_portal_group *);
extern u32 tcm_qla2xxx_get_pr_transport_id(struct se_portal_group *, struct se_node_acl *,
			struct t10_pr_registration *, int *, unsigned char *);
extern u32 tcm_qla2xxx_get_pr_transport_id_len(struct se_portal_group *, struct se_node_acl *,
			struct t10_pr_registration *, int *);
extern char *tcm_qla2xxx_parse_pr_out_transport_id(struct se_portal_group *, const char *,
				u32 *, char **);
extern int tcm_qla2xxx_check_demo_mode(struct se_portal_group *);
extern int tcm_qla2xxx_check_demo_mode_cache(struct se_portal_group *);
extern int tcm_qla2xxx_check_demo_write_protect(struct se_portal_group *);
extern int tcm_qla2xxx_check_prod_write_protect(struct se_portal_group *);
extern struct se_node_acl *tcm_qla2xxx_alloc_fabric_acl(struct se_portal_group *);
extern void tcm_qla2xxx_release_fabric_acl(struct se_portal_group *, struct se_node_acl *);
extern u32 tcm_qla2xxx_tpg_get_inst_index(struct se_portal_group *);
extern void tcm_qla2xxx_free_cmd(struct qla_tgt_cmd *);
extern int tcm_qla2xxx_check_stop_free(struct se_cmd *);
extern void tcm_qla2xxx_release_cmd(struct se_cmd *);
extern int tcm_qla2xxx_shutdown_session(struct se_session *);
extern void tcm_qla2xxx_close_session(struct se_session *);
extern void tcm_qla2xxx_stop_session(struct se_session *, int, int);
extern void tcm_qla2xxx_reset_nexus(struct se_session *);
extern int tcm_qla2xxx_sess_logged_in(struct se_session *);
extern u32 tcm_qla2xxx_sess_get_index(struct se_session *);
extern int tcm_qla2xxx_write_pending(struct se_cmd *);
extern int tcm_qla2xxx_write_pending_status(struct se_cmd *);
extern void tcm_qla2xxx_set_default_node_attrs(struct se_node_acl *);
extern u32 tcm_qla2xxx_get_task_tag(struct se_cmd *);
extern int tcm_qla2xxx_get_cmd_state(struct se_cmd *);
extern int tcm_qla2xxx_handle_cmd(struct scsi_qla_host *, struct qla_tgt_cmd *,
			unsigned char *, uint32_t, int, int, int);
extern int tcm_qla2xxx_new_cmd_map(struct se_cmd *);
extern int tcm_qla2xxx_handle_data(struct qla_tgt_cmd *);
extern int tcm_qla2xxx_handle_tmr(struct qla_tgt_mgmt_cmd *, uint32_t,
				uint8_t, uint32_t);
extern int tcm_qla2xxx_queue_data_in(struct se_cmd *);
extern int tcm_qla2xxx_queue_status(struct se_cmd *);
extern int tcm_qla2xxx_queue_tm_rsp(struct se_cmd *);
extern u16 tcm_qla2xxx_get_fabric_sense_len(void);
extern u16 tcm_qla2xxx_set_fabric_sense_len(struct se_cmd *, u32);
extern int tcm_qla2xxx_is_state_remove(struct se_cmd *);
