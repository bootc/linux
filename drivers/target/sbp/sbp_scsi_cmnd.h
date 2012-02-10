
#include "sbp_target_agent.h"

int sbp_run_transaction(struct fw_card *card, int tcode, int destination_id,
		int generation, int speed, unsigned long long offset,
		void *payload, size_t length);

void sbp_handle_command(struct sbp_target_request *req);
int sbp_rw_data(struct sbp_target_request *req);
int sbp_send_status(struct sbp_target_request *req);
int sbp_send_sense(struct sbp_target_request *req);
void sbp_free_request(struct sbp_target_request *req);
