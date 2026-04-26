/*
 * mail_pop.c
 *
 * Copyright (C) 2011-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MAIL_POP

#include "ndpi_api.h"
#include "ndpi_private.h"

/* Bitmask flags for observed POP3 client commands */
#define POP_BIT_AUTH		0x0001
#define POP_BIT_APOP		0x0002
#define POP_BIT_USER		0x0004
#define POP_BIT_PASS		0x0008
#define POP_BIT_CAPA		0x0010
#define POP_BIT_LIST		0x0020
#define POP_BIT_STAT		0x0040
#define POP_BIT_UIDL		0x0080
#define POP_BIT_RETR		0x0100
#define POP_BIT_DELE		0x0200
#define POP_BIT_STLS		0x0400

static void popInitExtraPacketProcessing(struct ndpi_flow_struct *flow);

/* **************************************** */

static void pop_set_detected(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow, u_int16_t protocol) {
  NDPI_LOG_INFO(ndpi_struct, "mail_pop identified\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, protocol,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* **************************************** */

static int pop_check_client_command(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(packet->payload_packet_len <= 4)
    return 0;

  if(ndpi_memcasecmp(packet->payload, "AUTH", 4) == 0) {
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_AUTH;
  } else if(ndpi_memcasecmp(packet->payload, "APOP", 4) == 0) {
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_APOP;
  } else if(ndpi_memcasecmp(packet->payload, "USER", 4) == 0) {
    char buf[64];

    ndpi_user_pwd_payload_copy((u_int8_t *)flow->l4.tcp.ftp_imap_pop_smtp.username,
                                sizeof(flow->l4.tcp.ftp_imap_pop_smtp.username),
                                5, packet->payload, packet->payload_packet_len);
    snprintf(buf, sizeof(buf), "Found username (%s)",
             flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, buf);
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_USER;
  } else if(ndpi_memcasecmp(packet->payload, "PASS", 4) == 0) {
    ndpi_user_pwd_payload_copy((u_int8_t *)flow->l4.tcp.ftp_imap_pop_smtp.password,
                                sizeof(flow->l4.tcp.ftp_imap_pop_smtp.password),
                                5, packet->payload, packet->payload_packet_len);
    ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, "Found password");
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_PASS;
  } else if(ndpi_memcasecmp(packet->payload, "CAPA", 4) == 0) {
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_CAPA;
  } else if(ndpi_memcasecmp(packet->payload, "LIST", 4) == 0) {
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_LIST;
  } else if(ndpi_memcasecmp(packet->payload, "STAT", 4) == 0) {
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_STAT;
  } else if(ndpi_memcasecmp(packet->payload, "UIDL", 4) == 0) {
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_UIDL;
  } else if(ndpi_memcasecmp(packet->payload, "RETR", 4) == 0) {
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_RETR;
  } else if(ndpi_memcasecmp(packet->payload, "DELE", 4) == 0) {
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_DELE;
  } else if(ndpi_memcasecmp(packet->payload, "STLS", 4) == 0) {
    flow->l4.tcp.pop_command_bitmask |= POP_BIT_STLS;
    flow->l4.tcp.mail_imap_starttls = 1;
  } else {
    return 0;
  }

  return 1;
}

/* **************************************** */

static void ndpi_search_mail_pop_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                                     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t bit_count = 0;

  NDPI_LOG_DBG(ndpi_struct, "search mail_pop\n");

  if(packet->payload_packet_len > 3 &&
     ndpi_memcasecmp(packet->payload, "+OK", 3) == 0) {
    /* Server positive response */
    flow->l4.tcp.mail_pop_stage += 1;
    if(flow->l4.tcp.mail_imap_starttls == 1) {
      NDPI_LOG_DBG2(ndpi_struct, "starttls detected\n");
      pop_set_detected(ndpi_struct, flow, NDPI_PROTOCOL_MAIL_POPS);
      if(ndpi_struct->cfg.pop_opportunistic_tls_enabled) {
        NDPI_LOG_DBG(ndpi_struct, "Switching to [%d/%d]\n",
                     flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);
        switch_extra_dissection_to_tls(ndpi_struct, flow);
        return;
      }
    }
  } else if(packet->payload_packet_len > 4 &&
            ndpi_memcasecmp(packet->payload, "-ERR", 4) == 0) {
    /* Server error response */
    flow->l4.tcp.mail_pop_stage += 1;
    if(flow->l4.tcp.mail_imap_starttls == 1)
      flow->l4.tcp.mail_imap_starttls = 0;
  } else if(!pop_check_client_command(ndpi_struct, flow)) {
    goto maybe_split_pop;
  }

  if(packet->payload_packet_len > 2 &&
     ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {
    if(flow->l4.tcp.pop_command_bitmask != 0) {
      u_int16_t mask = flow->l4.tcp.pop_command_bitmask;
      while(mask) {
        bit_count += mask & 1;
        mask >>= 1;
      }
    }

    NDPI_LOG_DBG2(ndpi_struct,
                  "mail_pop +OK/-ERR responses: %u, unique commands: %u\n",
                  flow->l4.tcp.mail_pop_stage, bit_count);

    if((bit_count + flow->l4.tcp.mail_pop_stage) >= 3) {
      if(flow->l4.tcp.mail_pop_stage > 0) {
        if(flow->l4.tcp.ftp_imap_pop_smtp.password[0] != '\0' ||
           flow->l4.tcp.mail_pop_stage >= 3) {
          pop_set_detected(ndpi_struct, flow, NDPI_PROTOCOL_MAIL_POP);
          if(flow->l4.tcp.ftp_imap_pop_smtp.password[0] == '\0')
            popInitExtraPacketProcessing(flow);
        }
      }
    }
    return;
  }

  /* Packet has no CRLF terminator — first fragment of a split packet */
  NDPI_LOG_DBG2(ndpi_struct, "mail_pop command without line ending -> skip\n");
  return;

 maybe_split_pop:
  if(((packet->payload_packet_len > 2 &&
       ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) ||
      flow->l4.tcp.pop_command_bitmask != 0 ||
      flow->l4.tcp.mail_pop_stage != 0) &&
     flow->packet_counter < 12) {
    NDPI_LOG_DBG2(ndpi_struct, "maybe part of split mail_pop packet -> skip\n");
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

/* **************************************** */

int ndpi_extra_search_mail_pop_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow) {
  int rc;

  ndpi_search_mail_pop_tcp(ndpi_struct, flow);
  rc = (flow->l4.tcp.ftp_imap_pop_smtp.password[0] == '\0') ? 1 : 0;

#ifdef POP_DEBUG
  printf("**** %s() [rc: %d]\n", __FUNCTION__, rc);
#endif

  return(rc);
}

/* **************************************** */

static void popInitExtraPacketProcessing(struct ndpi_flow_struct *flow) {
#ifdef POP_DEBUG
  printf("**** %s()\n", __FUNCTION__);
#endif
  flow->max_extra_packets_to_check = 7;
  flow->extra_packets_func = ndpi_extra_search_mail_pop_tcp;
}

/* **************************************** */

void init_mail_pop_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("MAIL_POP", ndpi_struct,
                          ndpi_search_mail_pop_tcp,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_MAIL_POP);
}
