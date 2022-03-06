/*
 * ftp_control.c
 *
 * Copyright (C) 2016-22 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FTP_CONTROL

#include "ndpi_api.h"

// #define FTP_DEBUG

/* *************************************************************** */

static void ndpi_int_ftp_control_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
						struct ndpi_flow_struct *flow) {

  flow->host_server_name[0] = '\0'; /* Remove any data set by other dissectors (eg. SMTP) */
  ndpi_set_detected_protocol(ndpi_struct, flow,
			     NDPI_PROTOCOL_FTP_CONTROL, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* *************************************************************** */

static int ndpi_ftp_control_check_request(struct ndpi_detection_module_struct *ndpi_struct,
					  struct ndpi_flow_struct *flow,
					  const u_int8_t *payload,
					  size_t payload_len) {
#ifdef FTP_DEBUG
  printf("%s() [%.*s]\n", __FUNCTION__, (int)payload_len, payload);
#endif

  if(ndpi_match_strprefix(payload, payload_len, "USER")) {
    ndpi_user_pwd_payload_copy((u_int8_t*)flow->l4.tcp.ftp_imap_pop_smtp.username,
			       sizeof(flow->l4.tcp.ftp_imap_pop_smtp.username), 5,
			       payload, payload_len);
    ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS);
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "PASS")) {
    ndpi_user_pwd_payload_copy((u_int8_t*)flow->l4.tcp.ftp_imap_pop_smtp.password,
			       sizeof(flow->l4.tcp.ftp_imap_pop_smtp.password), 5,
			       payload, payload_len);
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "AUTH") ||
     ndpi_match_strprefix(payload, payload_len, "auth")) {
    flow->l4.tcp.ftp_imap_pop_smtp.auth_found = 1;
    return 1;
  }
  /* ***************************************************** */

  if(ndpi_match_strprefix(payload, payload_len, "ABOR")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "ACCT")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "ADAT")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "ALLO")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "APPE")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "CCC")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "CDUP")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "CONF")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "CWD")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "DELE")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "ENC")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "EPRT")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "EPSV")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "FEAT")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "HELP")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "LANG")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "LIST")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "LPRT")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "LPSV")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "MDTM")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "MIC")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "MKD")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "MLSD")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "MLST")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "MODE")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "NLST")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "NOOP")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "OPTS")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "PASV")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "PBSZ")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "PORT")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "PROT")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "PWD")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "QUIT")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "REIN")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "REST")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "RETR")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "RMD")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "RNFR")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "RNTO")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "SITE")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "SIZE")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "SMNT")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "STAT")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "STOR")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "STOU")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "STRU")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "SYST")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "TYPE")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "XCUP")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "XMKD")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "XPWD")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "XRCP")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "XRMD")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "XRSQ")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "XSEM")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "XSEN")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "HOST")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "abor")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "acct")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "adat")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "allo")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "appe")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "ccc")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "cdup")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "conf")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "cwd")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "dele")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "enc")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "eprt")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "epsv")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "feat")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "help")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "lang")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "list")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "lprt")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "lpsv")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "mdtm")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "mic")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "mkd")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "mlsd")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "mlst")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "mode")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "nlst")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "noop")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "opts")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "pass")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "pasv")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "pbsz")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "port")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "prot")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "pwd")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "quit")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "rein")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "rest")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "retr")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "rmd")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "rnfr")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "rnto")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "site")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "size")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "smnt")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "stat")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "stor")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "stou")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "stru")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "syst")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "type")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "user")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "xcup")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "xmkd")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "xpwd")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "xrcp")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "xrmd")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "xrsq")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "xsem")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "xsen")) {
    return 1;
  }

  if(ndpi_match_strprefix(payload, payload_len, "host")) {
    return 1;
  }

  return 0;
}

/* *************************************************************** */

static int ndpi_ftp_control_check_response(struct ndpi_flow_struct *flow,
					   const u_int8_t *payload,
					   size_t payload_len) {
#ifdef FTP_DEBUG
  printf("%s() [%.*s]\n", __FUNCTION__, (int)payload_len, payload);
#endif

  if(payload_len == 0) return(1);

  switch(payload[0]) {
  case '1':
  case '2':
  case '3':
  case '6':
    if(flow->l4.tcp.ftp_imap_pop_smtp.auth_found == 1)
      flow->l4.tcp.ftp_imap_pop_smtp.auth_tls = 1;
    return(1);
    break;

  case '4':
  case '5':
    flow->l4.tcp.ftp_imap_pop_smtp.auth_failed = 1;
    flow->l4.tcp.ftp_imap_pop_smtp.auth_done = 1;
    return(1);
    break;
  }

  return 0;
}

/* *************************************************************** */

static void ndpi_check_ftp_control(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  /* Check connection over TCP */
  if(packet->tcp) {
    u_int16_t twentyfive = htons(25);
    
    /* Exclude SMTP, which uses similar commands. */
    if(packet->tcp->dest == twentyfive || packet->tcp->source == twentyfive) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    /* Break after 8 packets. */
    if(flow->packet_counter > 8) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    /* Check if we so far detected the protocol in the request or not. */
    if(flow->ftp_control_stage == 0) {
      NDPI_LOG_DBG2(ndpi_struct, "FTP_CONTROL stage 0: \n");

      if((payload_len > 0) && ndpi_ftp_control_check_request(ndpi_struct,
							     flow, packet->payload, payload_len)) {
	NDPI_LOG_DBG2(ndpi_struct,
		      "Possible FTP_CONTROL request detected, we will look further for the response..\n");

	/* 
	   Encode the direction of the packet in the stage, so we will know when we need
	   to look for the response packet. 
	*/
	flow->ftp_control_stage = packet->packet_direction + 1;
      }
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "FTP_CONTROL stage %u: \n", flow->ftp_control_stage);

      /*
	At first check, if this is for sure a response packet (in another direction.
	If not, do nothing now and return. 
      */
      if((flow->ftp_control_stage - packet->packet_direction) == 1) {
	return;
      }
      
      /* This is a packet in another direction. Check if we find the proper response. */
      if((payload_len > 0) && ndpi_ftp_control_check_response(flow, packet->payload, payload_len)) {
	NDPI_LOG_INFO(ndpi_struct, "found FTP_CONTROL\n");

#ifdef FTP_DEBUG
	printf("%s() [user: %s][pwd: %s]\n", __FUNCTION__,
	       flow->l4.tcp.ftp_imap_pop_smtp.username, flow->l4.tcp.ftp_imap_pop_smtp.password);
#endif

	if(flow->l4.tcp.ftp_imap_pop_smtp.password[0] == '\0' &&
	   flow->l4.tcp.ftp_imap_pop_smtp.auth_done == 0 &&
	   flow->l4.tcp.ftp_imap_pop_smtp.auth_tls == 0) /* TODO: any values on dissecting TLS handshake? */
	  flow->ftp_control_stage = 0;
	else
	  ndpi_int_ftp_control_add_connection(ndpi_struct, flow);
      } else {
	NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to FTP_CONTROL, "
		      "resetting the stage to 0\n");
	flow->ftp_control_stage = 0;
      }
    }
  }
}

/* *************************************************************** */

void ndpi_search_ftp_control(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow) {
  NDPI_LOG_DBG(ndpi_struct, "search FTP_CONTROL\n");

  /* skip marked packets */
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_FTP_CONTROL) {
    ndpi_check_ftp_control(ndpi_struct, flow);
  }
}

/* *************************************************************** */

void init_ftp_control_dissector(struct ndpi_detection_module_struct *ndpi_struct,
				u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("FTP_CONTROL", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_FTP_CONTROL,
				      ndpi_search_ftp_control,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
