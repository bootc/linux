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

#include "sbp_base.h"
#include "sbp_management_agent.h"
#include "sbp_login.h"
#include "sbp_target_agent.h"
#include "sbp_scsi_cmnd.h"

#define SESSION_MAINTENANCE_INTERVAL HZ

static atomic_t login_id = ATOMIC_INIT(0);

static void session_maintenance_work(struct work_struct *work);

static int read_peer_guid(u64 *guid, const struct sbp_management_request *req)
{
	int ret;
	__be32 high, low;

	ret = sbp_run_transaction(req->card, TCODE_READ_QUADLET_REQUEST,
			req->node_addr, req->generation, req->speed,
			(CSR_REGISTER_BASE | CSR_CONFIG_ROM) + 3 * 4,
			&high, sizeof(high));
	if (ret != RCODE_COMPLETE)
		return ret;

	ret = sbp_run_transaction(req->card, TCODE_READ_QUADLET_REQUEST,
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
	struct sbp_session *sess, *found = NULL;

	spin_lock_bh(&tpg->se_tpg.session_lock);
	list_for_each_entry(se_sess, &tpg->se_tpg.tpg_sess_list, sess_list) {
		sess = se_sess->fabric_sess_ptr;
		if (sess->guid == guid)
			found = sess;
	}
	spin_unlock_bh(&tpg->se_tpg.session_lock);

	return found;
}

static struct sbp_login_descriptor *sbp_login_find_by_lun(
		struct sbp_session *session, struct se_lun *lun)
{
	struct sbp_login_descriptor *login, *found = NULL;

	spin_lock_bh(&session->lock);
	list_for_each_entry(login, &session->login_list, link) {
		if (login->lun == lun)
			found = login;
	}
	spin_unlock_bh(&session->lock);

	return found;
}

static int sbp_login_count_all_by_lun(
		struct sbp_tpg *tpg,
		struct se_lun *lun,
		int exclusive)
{
	struct se_session *se_sess;
	struct sbp_session *sess;
	struct sbp_login_descriptor *login;
	int count = 0;

	spin_lock_bh(&tpg->se_tpg.session_lock);
	list_for_each_entry(se_sess, &tpg->se_tpg.tpg_sess_list, sess_list) {
		sess = se_sess->fabric_sess_ptr;

		spin_lock_bh(&sess->lock);
		list_for_each_entry(login, &sess->login_list, link) {
			if (login->lun != lun)
				continue;

			if (!exclusive || login->exclusive)
				count++;
		}
		spin_unlock_bh(&sess->lock);
	}
	spin_unlock_bh(&tpg->se_tpg.session_lock);

	return count;
}

static struct sbp_login_descriptor *sbp_login_find_by_id(
	struct sbp_tpg *tpg, int login_id)
{
	struct se_session *se_sess;
	struct sbp_session *sess;
	struct sbp_login_descriptor *login, *found = NULL;

	spin_lock_bh(&tpg->se_tpg.session_lock);
	list_for_each_entry(se_sess, &tpg->se_tpg.tpg_sess_list, sess_list) {
		sess = se_sess->fabric_sess_ptr;

		spin_lock_bh(&sess->lock);
		list_for_each_entry(login, &sess->login_list, link) {
			if (login->login_id == login_id)
				found = login;
		}
		spin_unlock_bh(&sess->lock);
	}
	spin_unlock_bh(&tpg->se_tpg.session_lock);

	return found;
}

static struct se_lun *sbp_get_lun_from_tpg(struct sbp_tpg *tpg, int lun)
{
	struct se_portal_group *se_tpg = &tpg->se_tpg;
	struct se_lun *se_lun;

	if (lun >= TRANSPORT_MAX_LUNS_PER_TPG)
		return ERR_PTR(-EINVAL);

	spin_lock(&se_tpg->tpg_lun_lock);
	se_lun = &se_tpg->tpg_lun_list[lun];

	if (se_lun->lun_status != TRANSPORT_LUN_STATUS_ACTIVE)
		se_lun = ERR_PTR(-ENODEV);

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
		pr_warn("Node ACL not found for %s\n", guid_str);

		transport_free_session(sess->se_sess);
		kfree(sess);

		return ERR_PTR(-EPERM);
	}

	sess->se_sess->se_node_acl = se_nacl;

	spin_lock_init(&sess->lock);
	INIT_LIST_HEAD(&sess->login_list);
	INIT_DELAYED_WORK(&sess->maint_work, session_maintenance_work);

	sess->guid = guid;

	transport_register_session(&tpg->se_tpg, se_nacl, sess->se_sess, sess);

	return sess;
}

static void sbp_session_release(struct sbp_session *sess, bool cancel_work)
{
	spin_lock_bh(&sess->lock);
	if (!list_empty(&sess->login_list)) {
		spin_unlock_bh(&sess->lock);
		return;
	}
	spin_unlock_bh(&sess->lock);

	if (cancel_work)
		cancel_delayed_work_sync(&sess->maint_work);

	transport_deregister_session_configfs(sess->se_sess);
	transport_deregister_session(sess->se_sess);

	if (sess->card)
		fw_card_put(sess->card);

	kfree(sess);
}

static void sbp_login_release(struct sbp_login_descriptor *login,
	bool cancel_work)
{
	struct sbp_session *sess = login->sess;

	/* FIXME: abort/wait on tasks */

	sbp_target_agent_unregister(login->tgt_agt);

	if (sess) {
		spin_lock_bh(&sess->lock);
		list_del(&login->link);
		spin_unlock_bh(&sess->lock);

		sbp_session_release(sess, cancel_work);
	}

	kfree(login);
}

void sbp_management_request_login(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size)
{
	struct sbp_tport *tport = agent->tport;
	struct sbp_tpg *tpg = tport->tpg;
	struct se_lun *se_lun;
	int ret;
	u64 guid;
	struct sbp_session *sess;
	struct sbp_login_descriptor *login;
	struct sbp_login_response_block *response;
	int login_response_len;

	se_lun = sbp_get_lun_from_tpg(tpg,
			LOGIN_ORB_LUN(be32_to_cpu(req->orb.misc)));
	if (IS_ERR(se_lun)) {
		pr_notice("login to unknown LUN: %d\n",
			LOGIN_ORB_LUN(be32_to_cpu(req->orb.misc)));

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_LUN_NOTSUPP));
		return;
	}

	ret = read_peer_guid(&guid, req);
	if (ret != RCODE_COMPLETE) {
		pr_warn("failed to read peer GUID: %d\n", ret);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_TRANSPORT_FAILURE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_UNSPECIFIED_ERROR));
		return;
	}

	pr_notice("mgt_agent LOGIN to LUN %d from %016llx\n",
		se_lun->unpacked_lun, guid);

	sess = sbp_session_find_by_guid(tpg, guid);
	if (sess) {
		login = sbp_login_find_by_lun(sess, se_lun);
		if (login) {
			pr_notice("initiator already logged-in\n");

			/*
			 * SBP-2 R4 says we should return access denied, but
			 * that can confuse initiators. Instead we need to
			 * treat this like a reconnect, but send the login
			 * response block like a fresh login.
			 *
			 * This is required particularly in the case of Apple
			 * devices booting off the FireWire target, where
			 * the firmware has an active login to the target. When
			 * the OS takes control of the session it issues its own
			 * LOGIN rather than a RECONNECT. To avoid the machine
			 * waiting until the reconnect_hold expires, we can skip
			 * the ACCESS_DENIED errors to speed things up.
			 */

			goto already_logged_in;
		}
	}

	/*
	 * check exclusive bit in login request
	 * reject with access_denied if any logins present
	 */
	if (LOGIN_ORB_EXCLUSIVE(be32_to_cpu(req->orb.misc)) &&
			sbp_login_count_all_by_lun(tpg, se_lun, 0)) {
		pr_warn("refusing exclusive login with other active logins\n");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_ACCESS_DENIED));
		return;
	}

	/*
	 * check exclusive bit in any existing login descriptor
	 * reject with access_denied if any exclusive logins present
	 */
	if (sbp_login_count_all_by_lun(tpg, se_lun, 1)) {
		pr_warn("refusing login while another exclusive login present\n");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_ACCESS_DENIED));
		return;
	}

	/*
	 * check we haven't exceeded the number of allowed logins
	 * reject with resources_unavailable if we have
	 */
	if (sbp_login_count_all_by_lun(tpg, se_lun, 0) >=
			tport->max_logins_per_lun) {
		pr_warn("max number of logins reached\n");

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

		schedule_delayed_work(&sess->maint_work,
				SESSION_MAINTENANCE_INTERVAL);
	}

	/* only take the latest reconnect_hold into account */
	sess->reconnect_hold = min(
		1 << LOGIN_ORB_RECONNECT(be32_to_cpu(req->orb.misc)),
		tport->max_reconnect_timeout) - 1;

	login = kmalloc(sizeof(*login), GFP_KERNEL);
	if (!login) {
		pr_err("failed to allocate login descriptor\n");

		sbp_session_release(sess, true);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_RESOURCES_UNAVAIL));
		return;
	}

	login->sess = sess;
	login->lun = se_lun;
	login->status_fifo_addr = sbp2_pointer_to_addr(&req->orb.status_fifo);
	login->exclusive = LOGIN_ORB_EXCLUSIVE(be32_to_cpu(req->orb.misc));
	login->login_id = atomic_inc_return(&login_id);

	login->tgt_agt = sbp_target_agent_register(login);
	if (IS_ERR(login->tgt_agt)) {
		ret = PTR_ERR(login->tgt_agt);
		pr_err("failed to map command block handler: %d\n", ret);

		sbp_session_release(sess, true);
		kfree(login);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_RESOURCES_UNAVAIL));
		return;
	}

	spin_lock_bh(&sess->lock);
	list_add_tail(&login->link, &sess->login_list);
	spin_unlock_bh(&sess->lock);

already_logged_in:
	response = kzalloc(sizeof(*response), GFP_KERNEL);
	if (!response) {
		pr_err("failed to allocate login response block\n");

		sbp_login_release(login, true);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_RESOURCES_UNAVAIL));
		return;
	}

	login_response_len = clamp_val(
			LOGIN_ORB_RESPONSE_LENGTH(be32_to_cpu(req->orb.length)),
			12, sizeof(*response));
	response->misc = cpu_to_be32(
		((login_response_len & 0xffff) << 16) |
		(login->login_id & 0xffff));
	response->reconnect_hold = cpu_to_be32(sess->reconnect_hold & 0xffff);
	addr_to_sbp2_pointer(login->tgt_agt->handler.offset,
		&response->command_block_agent);

	ret = sbp_run_transaction(sess->card, TCODE_WRITE_BLOCK_REQUEST,
		sess->node_id, sess->generation, sess->speed,
		sbp2_pointer_to_addr(&req->orb.ptr2), response,
		login_response_len);
	if (ret != RCODE_COMPLETE) {
		pr_debug("failed to write login response block: %x\n", ret);

		kfree(response);
		sbp_login_release(login, true);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_TRANSPORT_FAILURE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_UNSPECIFIED_ERROR));
		return;
	}

	kfree(response);

	req->status.status = cpu_to_be32(
		STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
		STATUS_BLOCK_SBP_STATUS(SBP_STATUS_OK));
}

void sbp_management_request_query_logins(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size)
{
	pr_notice("QUERY LOGINS not implemented\n");
	/* FIXME: implement */

	req->status.status = cpu_to_be32(
		STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
		STATUS_BLOCK_SBP_STATUS(SBP_STATUS_REQ_TYPE_NOTSUPP));
}

void sbp_management_request_reconnect(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size)
{
	struct sbp_tport *tport = agent->tport;
	struct sbp_tpg *tpg = tport->tpg;
	int ret;
	u64 guid;
	struct sbp_login_descriptor *login;

	ret = read_peer_guid(&guid, req);
	if (ret != RCODE_COMPLETE) {
		pr_warn("failed to read peer GUID: %d\n", ret);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_TRANSPORT_FAILURE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_UNSPECIFIED_ERROR));
		return;
	}

	pr_notice("mgt_agent RECONNECT from %016llx\n", guid);

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

	spin_lock_bh(&login->sess->lock);
	if (login->sess->card)
		fw_card_put(login->sess->card);

	/* update the node details */
	login->sess->generation = req->generation;
	login->sess->node_id = req->node_addr;
	login->sess->card = fw_card_get(req->card);
	login->sess->speed = req->speed;
	spin_unlock_bh(&login->sess->lock);

	req->status.status = cpu_to_be32(
		STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
		STATUS_BLOCK_SBP_STATUS(SBP_STATUS_OK));
}

void sbp_management_request_logout(
	struct sbp_management_agent *agent, struct sbp_management_request *req,
	int *status_data_size)
{
	struct sbp_tport *tport = agent->tport;
	struct sbp_tpg *tpg = tport->tpg;
	int login_id;
	struct sbp_login_descriptor *login;

	login_id = LOGOUT_ORB_LOGIN_ID(be32_to_cpu(req->orb.misc));

	login = sbp_login_find_by_id(tpg, login_id);
	if (!login) {
		pr_warn("cannot find login: %d\n", login_id);

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_LOGIN_ID_UNKNOWN));
		return;
	}

	pr_info("mgt_agent LOGOUT from LUN %d session %d\n",
		login->lun->unpacked_lun, login->login_id);

	if (req->node_addr != login->sess->node_id) {
		pr_warn("logout from different node ID\n");

		req->status.status = cpu_to_be32(
			STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
			STATUS_BLOCK_SBP_STATUS(SBP_STATUS_ACCESS_DENIED));
		return;
	}

	sbp_login_release(login, true);

	req->status.status = cpu_to_be32(
		STATUS_BLOCK_RESP(STATUS_RESP_REQUEST_COMPLETE) |
		STATUS_BLOCK_SBP_STATUS(SBP_STATUS_OK));
}

static void session_check_for_reset(struct sbp_session *sess)
{
	bool card_valid = false;

	spin_lock_bh(&sess->lock);

	if (sess->card) {
		spin_lock_irq(&sess->card->lock);
		card_valid = (sess->card->local_node != NULL);
		spin_unlock_irq(&sess->card->lock);

		if (!card_valid) {
			fw_card_put(sess->card);
			sess->card = NULL;
		}
	}

	if (!card_valid || (sess->generation != sess->card->generation)) {
		pr_info("Waiting for reconnect from node: %016llx\n",
				sess->guid);

		sess->node_id = -1;
		sess->reconnect_expires = get_jiffies_64() +
			((sess->reconnect_hold + 1) * HZ);
	}

	spin_unlock_bh(&sess->lock);
}

static void session_reconnect_expired(struct sbp_session *sess)
{
	struct sbp_login_descriptor *login, *temp;
	LIST_HEAD(login_list);

	pr_info("Reconnect timer expired for node: %016llx\n", sess->guid);

	spin_lock_bh(&sess->lock);
	list_for_each_entry_safe(login, temp, &sess->login_list, link) {
		login->sess = NULL;
		list_del(&login->link);
		list_add_tail(&login->link, &login_list);
	}
	spin_unlock_bh(&sess->lock);

	list_for_each_entry_safe(login, temp, &login_list, link) {
		list_del(&login->link);
		sbp_login_release(login, false);
	}

	sbp_session_release(sess, false);
}

static void session_maintenance_work(struct work_struct *work)
{
	struct sbp_session *sess = container_of(work, struct sbp_session,
			maint_work.work);

	/* could be called while tearing down the session */
	spin_lock_bh(&sess->lock);
	if (list_empty(&sess->login_list)) {
		spin_unlock_bh(&sess->lock);
		return;
	}
	spin_unlock_bh(&sess->lock);

	if (sess->node_id != -1) {
		/* check for bus reset and make node_id invalid */
		session_check_for_reset(sess);

		schedule_delayed_work(&sess->maint_work,
				SESSION_MAINTENANCE_INTERVAL);
	} else if (!time_after64(get_jiffies_64(), sess->reconnect_expires)) {
		/* still waiting for reconnect */
		schedule_delayed_work(&sess->maint_work,
				SESSION_MAINTENANCE_INTERVAL);
	} else {
		/* reconnect timeout has expired */
		session_reconnect_expired(sess);
	}
}

