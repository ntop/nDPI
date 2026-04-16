/*
 * irc.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_IRC

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_irc_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, ndpi_confidence_t confidence)
{
  NDPI_LOG_INFO(ndpi_struct, "Found IRC\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_IRC, NDPI_PROTOCOL_UNKNOWN, confidence);
}

static u_int8_t ndpi_check_for_NOTICE_or_PRIVMSG(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(ndpi_memmem(packet->payload, packet->payload_packet_len, "NOTICE", 6))
    return 1;
  if(ndpi_memmem(packet->payload, packet->payload_packet_len, "PRIVMSG", 7))
    return 1;
  return 0;
}

static void ndpi_search_irc_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
	
  NDPI_LOG_DBG(ndpi_struct, "search irc\n");

  /* Simple detection, expecially from the beginning of the flow */

  if(packet->payload_packet_len >= 8 &&
     (get_u_int8_t(packet->payload, packet->payload_packet_len - 1) == 0x0a ||
      ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0a00)) {

    if (memcmp(packet->payload, "USER ", 5) == 0 ||
	memcmp(packet->payload, "NICK ", 5) == 0 ||
	memcmp(packet->payload, "PASS ", 5) == 0 ||
	(memcmp(packet->payload, ":", 1) == 0 && ndpi_check_for_NOTICE_or_PRIVMSG(ndpi_struct) != 0) ||
	memcmp(packet->payload, "PONG ", 5) == 0 ||
	memcmp(packet->payload, "HELLO ", 6) == 0 ||
	memcmp(packet->payload, "YOURIP ", 7) == 0 ||
	memcmp(packet->payload, "PING ", 5) == 0 ||
	memcmp(packet->payload, "JOIN ", 5) == 0 ||
	memcmp(packet->payload, "MODE ", 5) == 0 ||
	memcmp(packet->payload, "NOTICE ", 7) == 0 ||
	memcmp(packet->payload, "PRIVMSG ", 8) == 0 ||
	memcmp(packet->payload, "VERSION ", 8) == 0) {
      char *user = ndpi_strnstr((char*)packet->payload, "USER ", packet->payload_packet_len);

      if(user) {
        char buf[32], msg[64], *sp;

        snprintf(buf, sizeof(buf), "%.*s", (int)(packet->payload_packet_len - (user + 5 - (char *)packet->payload)), user + 5);
	sp = buf;
	strsep(&sp, " \r\n");
	  
        snprintf(msg, sizeof(msg), "Found IRC username (%s)", buf);
        ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, msg);
      }

      NDPI_LOG_DBG2(ndpi_struct, "IRC stage: %d\n", flow->l4.tcp.irc_stage);
      flow->l4.tcp.irc_stage++;
      /* 3 consecutive valid packets */
      if(flow->l4.tcp.irc_stage == 3)
        ndpi_int_irc_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
      return;
    }
  }
  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_irc_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("IRC", ndpi_struct,
                     ndpi_search_irc_tcp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_IRC);
}

