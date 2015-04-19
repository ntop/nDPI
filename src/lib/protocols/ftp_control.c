/*
 * ftp_control.c
 *
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
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


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_FTP_CONTROL

static void ndpi_int_ftp_control_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FTP_CONTROL, NDPI_REAL_PROTOCOL);
}

static int ndpi_ftp_control_check_request(const u_int8_t *payload) {
  
  if (match_first_bytes(payload, "ABOR")) {
    return 1;
  }
      
  if (match_first_bytes(payload, "ACCT")) {
    return 1;
  }

  if (match_first_bytes(payload, "ADAT")) {
    return 1;
  }

  if (match_first_bytes(payload, "ALLO")) {
    return 1;
  }

  if (match_first_bytes(payload, "APPE")) {
    return 1;
  }

  if (match_first_bytes(payload, "AUTH")) {
    return 1;
  }
  if (match_first_bytes(payload, "CCC")) {
    return 1;
  }

  if (match_first_bytes(payload, "CDUP")) {
    return 1;
  }

  if (match_first_bytes(payload, "CONF")) {
    return 1;
  }

  if (match_first_bytes(payload, "CWD")) {
    return 1;
  }

  if (match_first_bytes(payload, "DELE")) {
    return 1;
  }

  if (match_first_bytes(payload, "ENC")) {
    return 1;
  }

  if (match_first_bytes(payload, "EPRT")) {
    return 1;
  }

  if (match_first_bytes(payload, "EPSV")) {
    return 1;
  }

  if (match_first_bytes(payload, "FEAT")) {
    return 1;
  }

  if (match_first_bytes(payload, "HELP")) {
    return 1;
  }

  if (match_first_bytes(payload, "LANG")) {
    return 1;
  }

  if (match_first_bytes(payload, "LIST")) {
    return 1;
  }

  if (match_first_bytes(payload, "LPRT")) {
    return 1;
  }

  if (match_first_bytes(payload, "LPSV")) {
    return 1;
  }

  if (match_first_bytes(payload, "MDTM")) {
    return 1;
  }

  if (match_first_bytes(payload, "MIC")) {
    return 1;
  }

  if (match_first_bytes(payload, "MKD")) {
    return 1;
  }

  if (match_first_bytes(payload, "MLSD")) {
    return 1;
  }

  if (match_first_bytes(payload, "MLST")) {
    return 1;
  }

  if (match_first_bytes(payload, "MODE")) {
    return 1;
  }

  if (match_first_bytes(payload, "NLST")) {
    return 1;
  }

  if (match_first_bytes(payload, "NOOP")) {
    return 1;
  }

  if (match_first_bytes(payload, "OPTS")) {
    return 1;
  }

  if (match_first_bytes(payload, "PASS")) {
    return 1;
  }

  if (match_first_bytes(payload, "PASV")) {
    return 1;
  }

  if (match_first_bytes(payload, "PBSZ")) {
    return 1;
  }

  if (match_first_bytes(payload, "PORT")) {
    return 1;
  }

  if (match_first_bytes(payload, "PROT")) {
    return 1;
  }

  if (match_first_bytes(payload, "PWD")) {
    return 1;
  }

  if (match_first_bytes(payload, "QUIT")) {
    return 1;
  }

  if (match_first_bytes(payload, "REIN")) {
    return 1;
  }

  if (match_first_bytes(payload, "REST")) {
    return 1;
  }

  if (match_first_bytes(payload, "RETR")) {
    return 1;
  }

  if (match_first_bytes(payload, "RMD")) {
    return 1;
  }

  if (match_first_bytes(payload, "RNFR")) {
    return 1;
  }

  if (match_first_bytes(payload, "RNTO")) {
    return 1;
  }

  if (match_first_bytes(payload, "SITE")) {
    return 1;
  }

  if (match_first_bytes(payload, "SIZE")) {
    return 1;
  }

  if (match_first_bytes(payload, "SMNT")) {
    return 1;
  }

  if (match_first_bytes(payload, "STAT")) {
    return 1;
  }

  if (match_first_bytes(payload, "STOR")) {
    return 1;
  }

  if (match_first_bytes(payload, "STOU")) {
    return 1;
  }

  if (match_first_bytes(payload, "STRU")) {
    return 1;
  }

  if (match_first_bytes(payload, "SYST")) {
    return 1;
  }

  if (match_first_bytes(payload, "TYPE")) {
    return 1;
  }

  if (match_first_bytes(payload, "USER")) {
    return 1;
  }

  if (match_first_bytes(payload, "XCUP")) {
    return 1;
  }

  if (match_first_bytes(payload, "XMKD")) {
    return 1;
  }

  if (match_first_bytes(payload, "XPWD")) {
    return 1;
  }

  if (match_first_bytes(payload, "XRCP")) {
    return 1;
  }

  if (match_first_bytes(payload, "XRMD")) {
    return 1;
  }

  if (match_first_bytes(payload, "XRSQ")) {
    return 1;
  }

  if (match_first_bytes(payload, "XSEM")) {
    return 1;
  }

  if (match_first_bytes(payload, "XSEN")) {
    return 1;
  }

  if (match_first_bytes(payload, "HOST")) {
    return 1;
  }

  if (match_first_bytes(payload, "abor")) {
    return 1;
  }

  if (match_first_bytes(payload, "acct")) {
    return 1;
  }

  if (match_first_bytes(payload, "adat")) {
    return 1;
  }

  if (match_first_bytes(payload, "allo")) {
    return 1;
  }

  if (match_first_bytes(payload, "appe")) {
    return 1;
  }

  if (match_first_bytes(payload, "auth")) {
    return 1;
  }

  if (match_first_bytes(payload, "ccc")) {
    return 1;
  }

  if (match_first_bytes(payload, "cdup")) {
    return 1;
  }

  if (match_first_bytes(payload, "conf")) {
    return 1;
  }

  if (match_first_bytes(payload, "cwd")) {
    return 1;
  }

  if (match_first_bytes(payload, "dele")) {
    return 1;
  }

  if (match_first_bytes(payload, "enc")) {
    return 1;
  }

  if (match_first_bytes(payload, "eprt")) {
    return 1;
  }

  if (match_first_bytes(payload, "epsv")) {
    return 1;
  }

  if (match_first_bytes(payload, "feat")) {
    return 1;
  }

  if (match_first_bytes(payload, "help")) {
    return 1;
  }

  if (match_first_bytes(payload, "lang")) {
    return 1;
  }

  if (match_first_bytes(payload, "list")) {
    return 1;
  }

  if (match_first_bytes(payload, "lprt")) {
    return 1;
  }

  if (match_first_bytes(payload, "lpsv")) {
    return 1;
  }

  if (match_first_bytes(payload, "mdtm")) {
    return 1;
  }

  if (match_first_bytes(payload, "mic")) {
    return 1;
  }

  if (match_first_bytes(payload, "mkd")) {
    return 1;
  }

  if (match_first_bytes(payload, "mlsd")) {
    return 1;
  }

  if (match_first_bytes(payload, "mlst")) {
    return 1;
  }

  if (match_first_bytes(payload, "mode")) {
    return 1;
  }

  if (match_first_bytes(payload, "nlst")) {
    return 1;
  }

  if (match_first_bytes(payload, "noop")) {
    return 1;
  }

  if (match_first_bytes(payload, "opts")) {
    return 1;
  }

  if (match_first_bytes(payload, "pass")) {
    return 1;
  }

  if (match_first_bytes(payload, "pasv")) {
    return 1;
  }

  if (match_first_bytes(payload, "pbsz")) {
    return 1;
  }

  if (match_first_bytes(payload, "port")) {
    return 1;
  }

  if (match_first_bytes(payload, "prot")) {
    return 1;
  }

  if (match_first_bytes(payload, "pwd")) {
    return 1;
  }

  if (match_first_bytes(payload, "quit")) {
    return 1;
  }

  if (match_first_bytes(payload, "rein")) {
    return 1;
  }

  if (match_first_bytes(payload, "rest")) {
    return 1;
  }

  if (match_first_bytes(payload, "retr")) {
    return 1;
  }

  if (match_first_bytes(payload, "rmd")) {
    return 1;
  }

  if (match_first_bytes(payload, "rnfr")) {
    return 1;
  }

  if (match_first_bytes(payload, "rnto")) {
    return 1;
  }

  if (match_first_bytes(payload, "site")) {
    return 1;
  }

  if (match_first_bytes(payload, "size")) {
    return 1;
  }

  if (match_first_bytes(payload, "smnt")) {
    return 1;
  }

  if (match_first_bytes(payload, "stat")) {
    return 1;
  }

  if (match_first_bytes(payload, "stor")) {
    return 1;
  }

  if (match_first_bytes(payload, "stou")) {
    return 1;
  }

  if (match_first_bytes(payload, "stru")) {
    return 1;
  }

  if (match_first_bytes(payload, "syst")) {
    return 1;
  }

  if (match_first_bytes(payload, "type")) {
    return 1;
  }

  if (match_first_bytes(payload, "user")) {
    return 1;
  }

  if (match_first_bytes(payload, "xcup")) {
    return 1;
  }

  if (match_first_bytes(payload, "xmkd")) {
    return 1;
  }

  if (match_first_bytes(payload, "xpwd")) {
    return 1;
  }

  if (match_first_bytes(payload, "xrcp")) {
    return 1;
  }

  if (match_first_bytes(payload, "xrmd")) {
    return 1;
  }

  if (match_first_bytes(payload, "xrsq")) {
    return 1;
  }

  if (match_first_bytes(payload, "xsem")) {
    return 1;
  }

  if (match_first_bytes(payload, "xsen")) {
    return 1;
  }

  if (match_first_bytes(payload, "host")) {
    return 1;
  }
  
  return 0;
}

static int ndpi_ftp_control_check_response(const u_int8_t *payload) {
  
  if (match_first_bytes(payload, "110-")) {
    return 1;
  }

  if (match_first_bytes(payload, "120-")) {
    return 1;
  }

  if (match_first_bytes(payload, "125-")) {
    return 1;
  }

  if (match_first_bytes(payload, "150-")) {
    return 1;
  }

  if (match_first_bytes(payload, "202-")) {
    return 1;
  }

  if (match_first_bytes(payload, "211-")) {
    return 1;
  }

  if (match_first_bytes(payload, "212-")) {
    return 1;
  }

  if (match_first_bytes(payload, "213-")) {
    return 1;
  }

  if (match_first_bytes(payload, "214-")) {
    return 1;
  }

  if (match_first_bytes(payload, "215-")) {
    return 1;
  }

  if (match_first_bytes(payload, "220-")) {
    return 1;
  }

  if (match_first_bytes(payload, "221-")) {
    return 1;
  }

  if (match_first_bytes(payload, "225-")) {
    return 1;
  }

  if (match_first_bytes(payload, "226-")) {
    return 1;
  }

  if (match_first_bytes(payload, "227-")) {
    return 1;
  }

  if (match_first_bytes(payload, "228-")) {
    return 1;
  }

  if (match_first_bytes(payload, "229-")) {
    return 1;
  }

  if (match_first_bytes(payload, "230-")) {
    return 1;
  }

  if (match_first_bytes(payload, "231-")) {
    return 1;
  }

  if (match_first_bytes(payload, "232-")) {
    return 1;
  }

  if (match_first_bytes(payload, "250-")) {
    return 1;
  }

  if (match_first_bytes(payload, "257-")) {
    return 1;
  }

  if (match_first_bytes(payload, "331-")) {
    return 1;
  }

  if (match_first_bytes(payload, "332-")) {
    return 1;
  }

  if (match_first_bytes(payload, "350-")) {
    return 1;
  }

  if (match_first_bytes(payload, "421-")) {
    return 1;
  }

  if (match_first_bytes(payload, "425-")) {
    return 1;
  }

  if (match_first_bytes(payload, "426-")) {
    return 1;
  }

  if (match_first_bytes(payload, "430-")) {
    return 1;
  }

  if (match_first_bytes(payload, "434-")) {
    return 1;
  }

  if (match_first_bytes(payload, "450-")) {
    return 1;
  }

  if (match_first_bytes(payload, "451-")) {
    return 1;
  }

  if (match_first_bytes(payload, "452-")) {
    return 1;
  }

  if (match_first_bytes(payload, "501-")) {
    return 1;
  }

  if (match_first_bytes(payload, "502-")) {
    return 1;
  }

  if (match_first_bytes(payload, "503-")) {
    return 1;
  }

  if (match_first_bytes(payload, "504-")) {
    return 1;
  }

  if (match_first_bytes(payload, "530-")) {
    return 1;
  }

  if (match_first_bytes(payload, "532-")) {
    return 1;
  }

  if (match_first_bytes(payload, "550-")) {
    return 1;
  }

  if (match_first_bytes(payload, "551-")) {
    return 1;
  }

  if (match_first_bytes(payload, "552-")) {
    return 1;
  }

  if (match_first_bytes(payload, "553-")) {
    return 1;
  }

  if (match_first_bytes(payload, "631-")) {
    return 1;
  }

  if (match_first_bytes(payload, "632-")) {
    return 1;
  }

  if (match_first_bytes(payload, "633-")) {
    return 1;
  }

  if (match_first_bytes(payload, "10054-")) {
    return 1;
  }

  if (match_first_bytes(payload, "10060-")) {
    return 1;
  }

  if (match_first_bytes(payload, "10061-")) {
    return 1;
  }

  if (match_first_bytes(payload, "10066-")) {
    return 1;
  }

  if (match_first_bytes(payload, "10068-")) {
    return 1;
  }

  if (match_first_bytes(payload, "110 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "120 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "125 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "150 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "202 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "211 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "212 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "213 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "214 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "215 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "220 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "221 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "225 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "226 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "227 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "228 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "229 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "230 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "231 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "232 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "250 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "257 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "331 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "332 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "350 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "421 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "425 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "426 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "430 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "434 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "450 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "451 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "452 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "501 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "502 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "503 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "504 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "530 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "532 ")) {
    return 1;
  }
  if (match_first_bytes(payload, "550 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "551 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "552 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "553 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "631 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "632 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "633 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "10054 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "10060 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "10061 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "10066 ")) {
    return 1;
  }

  if (match_first_bytes(payload, "10068 ")) {
    return 1;
  }

  return 0;
}

static void ndpi_check_ftp_control(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;  
  u_int32_t payload_len = packet->payload_packet_len;
  
  /* Exclude SMTP, which uses similar commands. */
  if (packet->tcp->dest == htons(25) || packet->tcp->source == htons(25)) {
    NDPI_LOG(NDPI_PROTOCOL_FTP_CONTROL, ndpi_struct, NDPI_LOG_DEBUG, "Exclude FTP_CONTROL.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FTP_CONTROL);
    return;
  }
  
  /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_LOG(NDPI_PROTOCOL_FTP_CONTROL, ndpi_struct, NDPI_LOG_DEBUG, "Exclude FTP_CONTROL.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FTP_CONTROL);
    return;
  }
  
  /* Check if we so far detected the protocol in the request or not. */
  if (flow->ftp_control_stage == 0) {
     NDPI_LOG(NDPI_PROTOCOL_FTP_CONTROL, ndpi_struct, NDPI_LOG_DEBUG, "FTP_CONTROL stage 0: \n");
     
     if ((payload_len > 0) && ndpi_ftp_control_check_request(packet->payload)) {
       NDPI_LOG(NDPI_PROTOCOL_FTP_CONTROL, ndpi_struct, NDPI_LOG_DEBUG, "Possible FTP_CONTROL request detected, we will look further for the response...\n");
       
       /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
       flow->ftp_control_stage = packet->packet_direction + 1;
     }
     
  } else {
    NDPI_LOG(NDPI_PROTOCOL_FTP_CONTROL, ndpi_struct, NDPI_LOG_DEBUG, "FTP_CONTROL stage %u: \n", flow->ftp_control_stage);
    
    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if ((flow->ftp_control_stage - packet->packet_direction) == 1) {
      return;
    }
    
    /* This is a packet in another direction. Check if we find the proper response. */
    if ((payload_len > 0) && ndpi_ftp_control_check_response(packet->payload)) {
      NDPI_LOG(NDPI_PROTOCOL_FTP_CONTROL, ndpi_struct, NDPI_LOG_DEBUG, "Found FTP_CONTROL.\n");
      ndpi_int_ftp_control_add_connection(ndpi_struct, flow);
    } else {
      NDPI_LOG(NDPI_PROTOCOL_FTP_CONTROL, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to FTP_CONTROL, resetting the stage to 0...\n");
      flow->ftp_control_stage = 0;
    }
    
  }
}

void ndpi_search_ftp_control(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_FTP_CONTROL, ndpi_struct, NDPI_LOG_DEBUG, "FTP_CONTROL detection...\n");

  /* skip marked packets */
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_FTP_CONTROL) {
    if (packet->tcp_retransmission == 0) {
      ndpi_check_ftp_control(ndpi_struct, flow);
    }
  }
}

#endif
