
int sbp_check_true(struct se_portal_group *);
int sbp_check_false(struct se_portal_group *);
char *sbp_get_fabric_name(void);
char *sbp_get_fabric_wwn(struct se_portal_group *);
u16 sbp_get_tag(struct se_portal_group *);
u32 sbp_get_default_depth(struct se_portal_group *);
struct se_node_acl *sbp_alloc_fabric_acl(struct se_portal_group *);
void sbp_release_fabric_acl(struct se_portal_group *,
		struct se_node_acl *);
u32 sbp_tpg_get_inst_index(struct se_portal_group *);
void sbp_release_cmd(struct se_cmd *se_cmd);
int sbp_shutdown_session(struct se_session *);
void sbp_close_session(struct se_session *);
void sbp_stop_session(struct se_session *, int, int);
void sbp_reset_nexus(struct se_session *);
int sbp_sess_logged_in(struct se_session *);
u32 sbp_sess_get_index(struct se_session *);
int sbp_write_pending(struct se_cmd *);
int sbp_write_pending_status(struct se_cmd *);
void sbp_set_default_node_attrs(struct se_node_acl *);
u32 sbp_get_task_tag(struct se_cmd *);
int sbp_get_cmd_state(struct se_cmd *);
int sbp_queue_data_in(struct se_cmd *);
int sbp_queue_status(struct se_cmd *);
int sbp_queue_tm_rsp(struct se_cmd *);
u16 sbp_set_fabric_sense_len(struct se_cmd *, u32);
u16 sbp_get_fabric_sense_len(void);
int sbp_is_state_remove(struct se_cmd *);

