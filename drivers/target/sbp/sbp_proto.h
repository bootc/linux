
u8 sbp_get_fabric_proto_ident(struct se_portal_group *se_tpg);
u32 sbp_get_pr_transport_id(struct se_portal_group *se_tpg,
		struct se_node_acl *se_nacl, struct t10_pr_registration *pr_reg,
		int *format_code, unsigned char *buf);
u32 sbp_get_pr_transport_id_len(
		struct se_portal_group *se_tpg, struct se_node_acl *se_nacl,
		struct t10_pr_registration *pr_reg, int *format_code);
char *sbp_parse_pr_out_transport_id(
		struct se_portal_group *se_tpg, const char *buf,
		u32 *out_tid_len, char **port_nexus_ptr);

