
#include "sbp_base.h"
#include "sbp_management_agent.h"

extern void sbp_management_request_login(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size);
extern void sbp_management_request_query_logins(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size);
extern void sbp_management_request_reconnect(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size);
extern void sbp_management_request_logout(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size);

