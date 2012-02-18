#ifndef _SBP_MANAGEMENT_AGENT_H
#define _SBP_MANAGEMENT_AGENT_H

#include <linux/types.h>
#include <linux/firewire.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "sbp_base.h"

struct sbp_management_agent {
	spinlock_t lock;
	struct sbp_tport *tport;
	struct fw_address_handler handler;
	int state;
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

struct sbp_management_agent *sbp_management_agent_register(
		struct sbp_tport *tport);
void sbp_management_agent_unregister(struct sbp_management_agent *agent);

#endif
