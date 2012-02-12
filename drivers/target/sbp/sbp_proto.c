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

#include <linux/kernel.h>
#include <linux/module.h>
#include <scsi/scsi.h>
#include <target/target_core_base.h>

#include "sbp_proto.h"

/*
 * Handlers for Serial Bus Protocol 2/3 (SBP-2 / SBP-3)
 */
u8 sbp_get_fabric_proto_ident(struct se_portal_group *se_tpg)
{
	/*
	 * Return a IEEE 1394 SCSI Protocol identifier for loopback operations
	 * This is defined in section 7.5.1 Table 362 in spc4r17
	 */
	return SCSI_PROTOCOL_SBP;
}

u32 sbp_get_pr_transport_id(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct t10_pr_registration *pr_reg,
	int *format_code,
	unsigned char *buf)
{
	int ret;

	/*
	 * Set PROTOCOL IDENTIFIER to 3h for SBP
	 */
	buf[0] = SCSI_PROTOCOL_SBP;
	/*
	 * From spc4r17, 7.5.4.4 TransportID for initiator ports using SCSI
	 * over IEEE 1394
	 */
	ret = hex2bin(&buf[8], se_nacl->initiatorname, 8);
	if (ret < 0)
		pr_debug("sbp transport_id: invalid hex string\n");

	/*
	 * The IEEE 1394 Transport ID is a hardcoded 24-byte length
	 */
	return 24;
}

u32 sbp_get_pr_transport_id_len(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct t10_pr_registration *pr_reg,
	int *format_code)
{
	*format_code = 0;
	/*
	 * From spc4r17, 7.5.4.4 TransportID for initiator ports using SCSI
	 * over IEEE 1394
	 *
	 * The SBP Transport ID is a hardcoded 24-byte length
	 */
	return 24;
}

/*
 * Used for handling SCSI fabric dependent TransportIDs in SPC-3 and above
 * Persistent Reservation SPEC_I_PT=1 and PROUT REGISTER_AND_MOVE operations.
 */
char *sbp_parse_pr_out_transport_id(
	struct se_portal_group *se_tpg,
	const char *buf,
	u32 *out_tid_len,
	char **port_nexus_ptr)
{
	/*
	 * Assume the FORMAT CODE 00b from spc4r17, 7.5.4.4 TransportID
	 * for initiator ports using SCSI over SBP Serial SCSI Protocol
	 *
	 * The TransportID for a IEEE 1394 Initiator Port is of fixed size of
	 * 24 bytes, and IEEE 1394 does not contain a I_T nexus identifier,
	 * so we return the **port_nexus_ptr set to NULL.
	 */
	*port_nexus_ptr = NULL;
	*out_tid_len = 24;

	return (char *)&buf[8];
}

