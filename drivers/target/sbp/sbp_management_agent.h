
struct sbp_management_agent {
	struct sbp_tpg *tpg;
	struct fw_address_handler handler;
	atomic_t state;
	struct work_struct work;
	u64 orb_offset;
	struct sbp_management_request *request;
};

struct sbp_management_request {
	struct sbp_management_orb orb;
	struct sbp_status_block status;
	struct fw_card *card;
	int generation;
	int node_addr;
	int speed;
};

struct sbp_management_agent *sbp_management_agent_register(struct sbp_tpg *tpg);
void sbp_management_agent_unregister(struct sbp_management_agent *agent);

