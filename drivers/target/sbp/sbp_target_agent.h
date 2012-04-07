#ifndef _SBP_TARGET_AGENT_H
#define _SBP_TARGET_AGENT_H

#include <linux/firewire.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <target/target_core_base.h>

#include "sbp_base.h"

struct sbp_target_agent {
	spinlock_t lock;
	struct fw_address_handler handler;
	struct sbp_login_descriptor *login;
	int state;
	struct work_struct work;
	u64 orb_pointer;
	bool doorbell;
};

struct sbp_rw_data_txn;

struct sbp_target_request {
	struct sbp_login_descriptor *login;
	u64 orb_pointer;
	struct sbp_command_block_orb orb;
	struct sbp_status_block status;
	struct work_struct work;

	struct se_cmd se_cmd;
	struct sbp_page_table_entry *pg_tbl;
	void *cmd_buf;

	unsigned char sense_buf[TRANSPORT_SENSE_BUFFER];
};

struct sbp_target_agent *sbp_target_agent_register(
		struct sbp_login_descriptor *login);
void sbp_target_agent_unregister(struct sbp_target_agent *agent);

#endif
