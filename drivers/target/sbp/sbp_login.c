/*
 * SBP2 target driver (SCSI over IEEE1394 in target mode)
 *
 * Copyright (C) 2011  Chris Boot <bootc@bootc.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define KMSG_COMPONENT "sbp_target"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/kref.h>
#include <linux/firewire.h>
#include <linux/firewire-constants.h>
#include <linux/slab.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>

#include "../../firewire/core.h"

#include "sbp_base.h"
#include "sbp_management_agent.h"
#include "sbp_login.h"
#include "sbp_target_agent.h"
#include "sbp_util.h"

static atomic_t login_id = ATOMIC_INIT(0);

static int read_peer_guid(u64 *guid, const struct sbp_management_request *req)
{
	int ret;
	__be32 high, low;

	ret = fw_run_transaction(req->card, TCODE_READ_QUADLET_REQUEST,
		req->node_addr, req->generation, req->speed,
		(CSR_REGISTER_BASE | CSR_CONFIG_ROM) + 3 * 4,
		&high, sizeof(high));
	if (ret != RCODE_COMPLETE)
		return ret;

	ret = fw_run_transaction(req->card, TCODE_READ_QUADLET_REQUEST,
		req->node_addr, req->generation, req->speed,
		(CSR_REGISTER_BASE | CSR_CONFIG_ROM) + 4 * 4,
		&low, sizeof(low));
	if (ret != RCODE_COMPLETE)
		return ret;

	*guid = (u64)be32_to_cpu(high) << 32 | be32_to_cpu(low);

	return RCODE_COMPLETE;
}

static struct sbp_session *sbp_session_find_by_guid(
	struct sbp_tpg *tpg, u64 guid)
{
	struct se_session *se_sess;

	list_for_each_entry(se_sess, &tpg->se_tpg.tpg_sess_list, sess_list) {
		struct sbp_session *sess = se_sess->fabric_sess_ptr;
		if (sess->guid == guid)
			return sess;
	}

	return NULL;
}

static struct sbp_login_descriptor *sbp_login_find_by_lun(
		struct sbp_session *session, struct se_lun *lun)
{
	struct sbp_login_descriptor *login;

	list_for_each_entry(login, &session->login_list, link) {
		if (login->lun == lun)
			return login;
	}

	return NULL;
}

static int sbp_login_count_all_by_lun(
		struct sbp_tpg *tpg,
		struct se_lun *lun,
		int exclusive)
{
	struct se_session *se_sess;
	int count = 0;

	list_for_each_entry(se_sess, &tpg->se_tpg.tpg_sess_list, sess_list) {
		struct sbp_session *sess = se_sess->fabric_sess_ptr;
		struct sbp_login_descriptor *login;

		list_for_each_entry(login, &sess->login_list, link) {
			if (login->lun != lun)
				continue;

			if (!exclusive) {
				count++;
				continue;
			}

			if (login->exclusive)
				count++;
		}
	}

	return count;
}

static struct sbp_login_descriptor *sbp_login_find_by_id(
	struct sbp_tpg *tpg, int login_id)
{
	struct se_session *se_sess;

	list_for_each_entry(se_sess, &tpg->se_tpg.tpg_sess_list, sess_list) {
		struct sbp_session *sess = se_sess->fabric_sess_ptr;
		struct sbp_login_descriptor *login;

		list_for_each_entry(login, &sess->login_list, link) {
			if (login->login_id == login_id)
				return login;
		}
	}

	return NULL;
}

static struct se_lun *sbp_get_lun_from_tpg(struct sbp_tpg *tpg, int lun)
{
	struct se_portal_group *se_tpg = &tpg->se_tpg;
	struct se_lun *se_lun;

	if (lun >= TRANSPORT_MAX_LUNS_PER_TPG)
		return ERR_PTR(-ENODEV);

	spin_lock(&se_tpg->tpg_lun_lock);
	se_lun = &se_tpg->tpg_lun_list[lun];

	if (se_lun->lun_status != TRANSPORT_LUN_STATUS_ACTIVE)
		se_lun = ERR_PTR(-EINVAL);

	spin_unlock(&se_tpg->tpg_lun_lock);

	return se_lun;
}

static struct sbp_session *sbp_session_create(
		struct sbp_tpg *tpg,
		u64 guid)
{
	struct sbp_session *sess;
	int ret;
	char guid_str[17];
	struct se_node_acl *se_nacl;

	sess = kmalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		pr_err("failed to allocate session descriptor\n");
		return ERR_PTR(-ENOMEM);
	}

	sess->se_sess = transport_init_session();
	if (IS_ERR(sess->se_sess)) {
		pr_err("failed to init se_session\n");

		ret = PTR_ERR(sess->se_sess);
		kfree(sess);
		return ERR_PTR(ret);
	}

	snprintf(guid_str, sizeof(guid_str), "%016llx", guid);

	se_nacl = core_tpg_check_initiator_node_acl(&tpg->se_tpg, guid_str);
	if (!se_nacl) {
		pr_warn("NodeACL not found for %s\n", guid_str);

		transport_free_session(sess->se_sess);
		kfree(sess);

		return ERR_PTR(-EPERM);
	}

	INIT_LIST_HEAD(&sess->login_list);
	sess->se_sess->se_node_acl = se_nacl;
	sess->guid = guid;

	transport_register_session(&tpg->se_tpg, se_nacl, sess->se_sess, sess);

	return sess;
}

static void sbp_session_release(struct sbp_session *sess)
{
	if (!list_empty(&sess->login_list))
		return;

	transport_deregister_session_configfs(sess->se_sess);
	transport_deregister_session(sess->se_sess);

	if (sess->card)
		fw_card_put(sess->card);

	kfree(sess);
}

static void sbp_login_release(struct sbp_login_descriptor *login)
{
	/* FIXME: abort/wait on tasks */

	list_del(&login->link);
	sbp_target_agent_unregister(login->tgt_agt);
	sbp_session_release(login->sess);
	kfree(login);
}

void sbp_management_request_login(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size)
{
	struct sbp_tpg *tpg = agent->tpg;
	struct se_lun *lun;
	int ret;
	u64 guid;
	struct sbp_session *sess;
	struct sbp_login_descriptor *login;
	struct sbp_login_response_block *response;
	int login_response_len;

	/* find the LUN we want to login to */
	lun = sbp_get_lun_from_tpg(tpg,
			LOGIN_ORB_LUN(be32_to_cpu(req->orb.misc)));
	if (IS_ERR(lun)) {
		pr_notice("login to unknown LUN: %d",
			LOGIN_ORB_LUN(be32_to_cpu(req->orb.misc)));

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_LUN_NOTSUPP));
		return;
	}

	/* read the peer's GUID */
	ret = read_peer_guid(&guid, req);
	if (ret != RCODE_COMPLETE) {
		pr_warn("failed to read peer GUID: %d", ret);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_TRANSPORT_FAILURE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_UNSPECIFIED_ERROR));
		return;
	}

	pr_notice("mgt_agent LOGIN to LUN %d from %016llx\n",
		lun->unpacked_lun, guid);

	/* locate an existing session if there is one */
	sess = sbp_session_find_by_guid(tpg, guid);

	/*
	 * check for any existing logins by comparing GUIDs
	 * reject with access_denied if present
	 */
	if (sess) {
		login = sbp_login_find_by_lun(sess, lun);
		if (login) {
			pr_warn("initiator already logged-in");

			/*
			 * SBP-2 R4 says we should return access denied, but
			 * that can confuse initiators. Instead we need to
			 * treat this like a reconnect, but send the login
			 * response block like a fresh login.
			 */

			goto already_logged_in;
		}
	}

	/*
	 * check exclusive bit in login request
	 * reject with access_denied if any logins present
	 */
	if (LOGIN_ORB_EXCLUSIVE(be32_to_cpu(req->orb.misc)) &&
		sbp_login_count_all_by_lun(tpg, lun, 0)) {
		pr_warn("refusing exclusive login with other active logins");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_ACCESS_DENIED));
		return;
	}

	/*
	 * check exclusive bit in any existing login descriptor
	 * reject with access_denied if any exclusive logins present
	 */
	if (sbp_login_count_all_by_lun(tpg, lun, 1)) {
		pr_warn("refusing login while another exclusive login present");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_ACCESS_DENIED));
		return;
	}

	/*
	 * check we haven't exceeded the number of allowed logins
	 * reject with resources_unavailable if we have
	 */
	if (sbp_login_count_all_by_lun(tpg, lun, 0) >=
		tpg->max_logins_per_lun) {
		pr_warn("max number of logins reached");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_RESOURCES_UNAVAIL));
		return;
	}

	if (!sess) {
		sess = sbp_session_create(tpg, guid);
		if (IS_ERR(sess)) {
			switch (PTR_ERR(sess)) {
			case -EPERM:
				ret = SBP_STATUS_ACCESS_DENIED;
				break;
			default:
				ret = SBP_STATUS_RESOURCES_UNAVAIL;
				break;
			}

			req->status.status = cpu_to_be32(
				STATUS_BLOCK_RESP(
					STATUS_RESP_REQUEST_COMPLETE) |
				STATUS_BLOCK_SBP_STATUS(ret));
			return;
		}

		sess->node_id = req->node_addr;
		sess->card = fw_card_get(req->card);
		sess->generation = req->generation;
		sess->speed = req->speed;
	}

	/* create new login descriptor */
	login = kmalloc(sizeof(*login), GFP_KERNEL);
	if (!login) {
		pr_err("failed to allocate login descriptor\n");

		sbp_session_release(sess);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_RESOURCES_UNAVAIL));
		return;
	}

	login->sess = sess;
	login->lun = lun;
	login->status_fifo_addr = sbp2_pointer_to_addr(&req->orb.status_fifo);
	login->exclusive = LOGIN_ORB_EXCLUSIVE(be32_to_cpu(req->orb.misc));
	login->reconnect_hold = 30; /* FIXME */
	login->login_id = atomic_inc_return(&login_id);
	atomic_set(&login->unsolicited_status_enable, 0);

	/* set up address handler */
	login->tgt_agt = sbp_target_agent_register(login);
	if (IS_ERR(login->tgt_agt)) {
		ret = PTR_ERR(login->tgt_agt);
		pr_err("failed to map command block handler: %d\n", ret);

		sbp_session_release(sess);
		kfree(login);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_RESOURCES_UNAVAIL));
		return;
	}

	/* add to logins list */
	list_add_tail(&login->link, &sess->login_list);

already_logged_in:
	/* send login response */
	response = kzalloc(sizeof(*response), GFP_KERNEL);
	if (!response) {
		pr_err("failed to allocate login response block\n");

		sbp_login_release(login);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_RESOURCES_UNAVAIL));
		return;
	}

	login_response_len = max(12, min((int)sizeof(response),
		(int)LOGIN_ORB_RESPONSE_LENGTH(be32_to_cpu(req->orb.length))));
	response->misc = cpu_to_be32(
		((login_response_len & 0xffff) << 16) |
		(login->login_id & 0xffff));
	response->reconnect_hold = cpu_to_be32(login->reconnect_hold & 0xffff);
	addr_to_sbp2_pointer(login->tgt_agt->handler.offset,
		&response->command_block_agent);

	ret = fw_run_transaction(sess->card, TCODE_WRITE_BLOCK_REQUEST,
		sess->node_id, sess->generation, sess->speed,
		sbp2_pointer_to_addr(&req->orb.ptr2), response,
		login_response_len);
	if (ret != RCODE_COMPLETE) {
		pr_warn("failed to write login response block: %d\n", ret);

		kfree(response);
		sbp_login_release(login);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_TRANSPORT_FAILURE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_UNSPECIFIED_ERROR));
		return;
	}

	pr_notice("mgt_agent LOGIN to LUN %d from %016llx session %d\n",
		lun->unpacked_lun, guid, login->login_id);

	kfree(response);

	req->status.status = cpu_to_be32(
		STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
		STATUS_BLOCK_SBP_STATUS(SBP_STATUS_OK));
}

void sbp_management_request_query_logins(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size)
{
	pr_notice("mgt_agent QUERY LOGINS\n");
	/* FIXME: implement */

	req->status.status = cpu_to_be32(
		STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
		STATUS_BLOCK_SBP_STATUS(SBP_STATUS_REQ_TYPE_NOTSUPP));
}

void sbp_management_request_reconnect(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size)
{
	struct sbp_tpg *tpg = agent->tpg;
	int ret;
	u64 guid;
	struct sbp_login_descriptor *login;

	/* read the peer's GUID */
	ret = read_peer_guid(&guid, req);
	if (ret != RCODE_COMPLETE) {
		pr_warn("failed to read peer GUID: %d", ret);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_TRANSPORT_FAILURE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_UNSPECIFIED_ERROR));
		return;
	}

	pr_notice("mgt_agent RECONNECT from %016llx\n", guid);

	/* find the login */
	login = sbp_login_find_by_id(tpg,
		RECONNECT_ORB_LOGIN_ID(be32_to_cpu(req->orb.misc)));

	if (!login) {
		pr_err("mgt_agent RECONNECT unknown login ID\n");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_ACCESS_DENIED));
		return;
	}

	if (login->sess->guid != guid) {
		pr_err("mgt_agent RECONNECT login GUID doesn't match\n");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_ACCESS_DENIED));
		return;
	}

	/* update the node details */
	login->sess->generation = req->generation;
	login->sess->node_id = req->node_addr;
	login->sess->card = fw_card_get(req->card);
	login->sess->speed = req->speed;

	req->status.status = cpu_to_be32(
		STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
		STATUS_BLOCK_SBP_STATUS(SBP_STATUS_OK));
}

void sbp_management_request_logout(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size)
{
	struct sbp_tpg *tpg = agent->tpg;
	int login_id;
	struct sbp_login_descriptor *login;

	login_id = LOGOUT_ORB_LOGIN_ID(be32_to_cpu(req->orb.misc));

	/* Find login by ID */
	login = sbp_login_find_by_id(tpg, login_id);
	if (!login) {
		pr_warn("cannot find login: %d", login_id);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_LOGIN_ID_UNKNOWN));
		return;
	}

	pr_info("mgt_agent LOGOUT from LUN %d session %d\n",
		login->lun->unpacked_lun, login->login_id);

	/* Check source against login's node_id */
	if (req->node_addr != login->sess->node_id) {
		pr_warn("logout from different node ID");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_ACCESS_DENIED));
		return;
	}

	/* FIXME: Abort all pending operations */

	/* Perform logout */
	sbp_login_release(login);

	pr_info("logout successful!\n");

	req->status.status = cpu_to_be32(
		STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
		STATUS_BLOCK_SBP_STATUS(SBP_STATUS_OK));
}

