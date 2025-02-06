/*
 * irc.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-22 - ntop.org
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

static u_int8_t ndpi_check_for_Nickname(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t i, packetl = packet->payload_packet_len;

  if (packetl < 4) {
    return 0;
  }

  for (i = 0; i < (packetl - 4); i++) {
    if (packet->payload[i] == 'N' || packet->payload[i] == 'n') {
      if ((((packetl - (i + 1)) >= 4) && memcmp(&packet->payload[i + 1], "ick=", 4) == 0)
	  || (((packetl - (i + 1)) >= 8) && (memcmp(&packet->payload[i + 1], "ickname=", 8) == 0))
	  || (((packetl - (i + 1)) >= 8) && (memcmp(&packet->payload[i + 1], "ickName=", 8) == 0))) {
	NDPI_LOG_DBG2(ndpi_struct, "found HTTP IRC Nickname pattern\n");
	return 1;
      }
    }
  }
  return 0;
}

static u_int8_t ndpi_check_for_cmd(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t i;

  if (packet->payload_packet_len < 4) {
    return 0;
  }

  for (i = 0; i < packet->payload_packet_len - 4; i++) {
    if (packet->payload[i] == 'c') {
      if (memcmp(&packet->payload[i + 1], "md=", 3) == 0) {
	NDPI_LOG_DBG2(ndpi_struct, "found HTTP IRC cmd pattern  \n");
	return 1;
      }
    }
  }
  return 0;
}

static void ndpi_search_irc_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
	
  u_int16_t c = 0;
  u_int16_t i = 0;
  u_int16_t http_content_ptr_len = 0;

  NDPI_LOG_DBG(ndpi_struct, "search irc\n");
  if((flow->detected_protocol_stack[0] != NDPI_PROTOCOL_IRC && (flow->packet_counter > 10))
     || (flow->packet_counter >= 10)) {
    NDPI_LOG_DBG(ndpi_struct, "exclude irc, packet_counter too high0\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_IRC);
    return;
  }

  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_IRC && flow->packet_counter < 20
      && packet->payload_packet_len >= 8) {
    if (get_u_int8_t(packet->payload, packet->payload_packet_len - 1) == 0x0a
	|| (ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0a00)) {
      if (memcmp(packet->payload, ":", 1) == 0) {
	if (packet->payload[packet->payload_packet_len - 2] != 0x0d
	    && packet->payload[packet->payload_packet_len - 1] == 0x0a) {
	  ndpi_parse_packet_line_info_any(ndpi_struct);
	} else if (packet->payload[packet->payload_packet_len - 2] == 0x0d) {
	  ndpi_parse_packet_line_info(ndpi_struct, flow);
	} else {
	  flow->l4.tcp.irc_3a_counter++;
	  packet->parsed_lines = 0;
	}
	for (i = 0; i < packet->parsed_lines; i++) {
	  if ((packet->line[i].len > 0) && packet->line[i].ptr[0] == ':') {
	    flow->l4.tcp.irc_3a_counter++;
	    if (flow->l4.tcp.irc_3a_counter == 7) {	/* ':' == 0x3a */
	      NDPI_LOG_INFO(ndpi_struct, "found irc. 0x3a. seven times.");
	      ndpi_int_irc_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
	      return;
	    }
	  }
	}
	if (flow->l4.tcp.irc_3a_counter == 7) {	/* ':' == 0x3a */
	  NDPI_LOG_INFO(ndpi_struct, "found irc. 0x3a. seven times.");
	  ndpi_int_irc_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
	  return;
	}
      }

      if ((memcmp(packet->payload, "USER ", 5) == 0)
	  || (memcmp(packet->payload, "NICK ", 5) == 0)
	  || (memcmp(packet->payload, "PASS ", 5) == 0)
	  || (memcmp(packet->payload, ":", 1) == 0 && ndpi_check_for_NOTICE_or_PRIVMSG(ndpi_struct) != 0)
	  || (memcmp(packet->payload, "PONG ", 5) == 0)
	  || (memcmp(packet->payload, "PING ", 5) == 0)
	  || (memcmp(packet->payload, "JOIN ", 5) == 0)
	  || (memcmp(packet->payload, "MODE ", 5) == 0)
	  || (memcmp(packet->payload, "NOTICE ", 7) == 0)
	  || (memcmp(packet->payload, "PRIVMSG ", 8) == 0)
	  || (memcmp(packet->payload, "VERSION ", 8) == 0)) {
	char *user = ndpi_strnstr((char*)packet->payload, "USER ", packet->payload_packet_len);

	if(user) {
	  char buf[32], msg[64], *sp;

	  snprintf(buf, sizeof(buf), "%.*s", (int)(packet->payload_packet_len - (user + 5 - (char *)packet->payload)), user + 5);
	  if((sp = strchr(buf, ' ')) != NULL)
	    sp[0] = '\0';
	  
	  snprintf(msg, sizeof(msg), "Found IRC username (%s)", buf);
	  ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, msg);
	}
	
	NDPI_LOG_DBG2(ndpi_struct,
		      "USER, NICK, PASS, NOTICE, PRIVMSG one time");
	if (flow->l4.tcp.irc_stage == 2) {
	  NDPI_LOG_INFO(ndpi_struct, "found irc");
	  ndpi_int_irc_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
	  flow->l4.tcp.irc_stage = 3;
	}
	if (flow->l4.tcp.irc_stage == 1) {
	  NDPI_LOG_DBG2(ndpi_struct, "second time, stage=2");
	  flow->l4.tcp.irc_stage = 2;
	}
	if (flow->l4.tcp.irc_stage == 0) {
	  NDPI_LOG_DBG2(ndpi_struct, "first time, stage=1");
	  flow->l4.tcp.irc_stage = 1;
	}
	/* irc packets can have either windows line breaks (0d0a) or unix line breaks (0a) */
	if (packet->payload[packet->payload_packet_len - 2] == 0x0d
	    && packet->payload[packet->payload_packet_len - 1] == 0x0a) {
	  ndpi_parse_packet_line_info(ndpi_struct, flow);
	  if (packet->parsed_lines > 1) {
	    NDPI_LOG_DBG2(ndpi_struct, "packet contains more than one line");
	    for (c = 1; c < packet->parsed_lines; c++) {
	      if (packet->line[c].len > 4 && (memcmp(packet->line[c].ptr, "NICK ", 5) == 0
					      || memcmp(packet->line[c].ptr, "USER ", 5) == 0)) {
		NDPI_LOG_INFO(ndpi_struct, "found IRC: two icq signal words in the same packet");
		ndpi_int_irc_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
		flow->l4.tcp.irc_stage = 3;
		return;
	      }
	    }
	  }

	} else if (packet->payload[packet->payload_packet_len - 1] == 0x0a) {
	  ndpi_parse_packet_line_info_any(ndpi_struct);
	  if (packet->parsed_lines > 1) {
	    NDPI_LOG_DBG2(ndpi_struct, "packet contains more than one line");
	    for (c = 1; c < packet->parsed_lines; c++) {
	      if (packet->line[c].len > 4 && (memcmp(packet->line[c].ptr, "NICK ", 5) == 0
					      || memcmp(packet->line[c].ptr, "USER ",
							5) == 0)) {
		NDPI_LOG_INFO(ndpi_struct, "found IRC: two icq signal words in the same packet");
		ndpi_int_irc_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
		flow->l4.tcp.irc_stage = 3;
		return;
	      }
	    }
	  }
	}
      }
    }
  }

  if ((flow->detected_protocol_stack[0] != NDPI_PROTOCOL_IRC) && (flow->l4.tcp.irc_stage == 1)) {
    if ((((packet->payload_packet_len - http_content_ptr_len) > 10)
	 && (memcmp(packet->payload + http_content_ptr_len, "interface=", 10) == 0)
	 && (ndpi_check_for_Nickname(ndpi_struct) != 0))
	|| (((packet->payload_packet_len - http_content_ptr_len) > 5)
	    && (memcmp(packet->payload + http_content_ptr_len, "item=", 5) == 0)
	    && (ndpi_check_for_cmd(ndpi_struct) != 0))) {
      NDPI_LOG_INFO(ndpi_struct, "found IRC: Nickname, cmd,  one time");
      ndpi_int_irc_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
      return;
    }
  }
}

void init_irc_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("IRC", ndpi_struct, *id,
				      NDPI_PROTOCOL_IRC,
				      ndpi_search_irc_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

