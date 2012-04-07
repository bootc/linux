int tcm_vhost_check_true(struct se_portal_group *);
int tcm_vhost_check_false(struct se_portal_group *);
char *tcm_vhost_get_fabric_name(void);
u8 tcm_vhost_get_fabric_proto_ident(struct se_portal_group *);
char *tcm_vhost_get_fabric_wwn(struct se_portal_group *);
u16 tcm_vhost_get_tag(struct se_portal_group *);
u32 tcm_vhost_get_default_depth(struct se_portal_group *);
u32 tcm_vhost_get_pr_transport_id(struct se_portal_group *,
			struct se_node_acl *, struct t10_pr_registration *,
			int *, unsigned char *);
u32 tcm_vhost_get_pr_transport_id_len(struct se_portal_group *,
			struct se_node_acl *, struct t10_pr_registration *,
			int *);
char *tcm_vhost_parse_pr_out_transport_id(struct se_portal_group *,
			const char *, u32 *, char **);
struct se_node_acl *tcm_vhost_alloc_fabric_acl(struct se_portal_group *);
void tcm_vhost_release_fabric_acl(struct se_portal_group *,
			struct se_node_acl *);
u32 tcm_vhost_tpg_get_inst_index(struct se_portal_group *);
int tcm_vhost_new_cmd_map(struct se_cmd *);
void tcm_vhost_release_cmd(struct se_cmd *);
int tcm_vhost_shutdown_session(struct se_session *);
void tcm_vhost_close_session(struct se_session *);
u32 tcm_vhost_sess_get_index(struct se_session *);
int tcm_vhost_write_pending(struct se_cmd *);
int tcm_vhost_write_pending_status(struct se_cmd *);
void tcm_vhost_set_default_node_attrs(struct se_node_acl *);
u32 tcm_vhost_get_task_tag(struct se_cmd *);
int tcm_vhost_get_cmd_state(struct se_cmd *);
int tcm_vhost_queue_data_in(struct se_cmd *);
int tcm_vhost_queue_status(struct se_cmd *);
int tcm_vhost_queue_tm_rsp(struct se_cmd *);
u16 tcm_vhost_set_fabric_sense_len(struct se_cmd *, u32);
u16 tcm_vhost_get_fabric_sense_len(void);
