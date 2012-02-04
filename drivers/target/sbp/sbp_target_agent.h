
struct sbp_target_agent {
	struct fw_address_handler handler;
	struct sbp_login_descriptor *login;
	atomic_t state;
	struct work_struct work;
	u64 orb_pointer;
};

struct sbp_target_request {
	struct sbp_target_agent *agent;
	struct sbp_command_block_orb orb;
	struct sbp_status_block status;
	struct work_struct work;

	struct se_cmd se_cmd;
	void *cmd_buf;
	int unpacked_lun;
	u32 data_len;
	enum dma_data_direction	data_dir;
	void *data_buf;

	unsigned char sense_buf[TRANSPORT_SENSE_BUFFER];
};

struct sbp_target_agent *sbp_target_agent_register(
		struct sbp_login_descriptor *login);
void sbp_target_agent_unregister(struct sbp_target_agent *agent);
