
#include "sbp_target_agent.h"

void sbp_handle_command(struct sbp_target_request *req);
int sbp_rw_data(struct sbp_target_request *req);
int sbp_send_status(struct sbp_target_request *req);
int sbp_send_sense(struct sbp_target_request *req);
void sbp_free_request(struct sbp_target_request *req);
