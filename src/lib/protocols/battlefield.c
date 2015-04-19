/*
 * battlefield.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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


#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_BATTLEFIELD


static void ndpi_int_battlefield_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_BATTLEFIELD, NDPI_REAL_PROTOCOL);

  if (src != NULL) {
    src->battlefield_ts = packet->tick_timestamp;
  }
  if (dst != NULL) {
    dst->battlefield_ts = packet->tick_timestamp;
  }
}

void ndpi_search_battlefield(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_BATTLEFIELD) {
    if (src != NULL && ((u_int32_t)
			(packet->tick_timestamp - src->battlefield_ts) < ndpi_struct->battlefield_timeout)) {
      NDPI_LOG(NDPI_PROTOCOL_BATTLEFIELD, ndpi_struct, NDPI_LOG_DEBUG,
	       "battlefield : save src connection packet detected\n");
      src->battlefield_ts = packet->tick_timestamp;
    } else if (dst != NULL && ((u_int32_t)
			       (packet->tick_timestamp - dst->battlefield_ts) < ndpi_struct->battlefield_timeout)) {
      NDPI_LOG(NDPI_PROTOCOL_BATTLEFIELD, ndpi_struct, NDPI_LOG_DEBUG,
	       "battlefield : save dst connection packet detected\n");
      dst->battlefield_ts = packet->tick_timestamp;
    }
    return;
  }

  if (NDPI_SRC_OR_DST_HAS_PROTOCOL(src, dst, NDPI_PROTOCOL_BATTLEFIELD)) {
    if (flow->l4.udp.battlefield_stage == 0 || flow->l4.udp.battlefield_stage == 1 + packet->packet_direction) {
      if (packet->payload_packet_len > 8 && get_u_int16_t(packet->payload, 0) == htons(0xfefd)) {
	flow->l4.udp.battlefield_msg_id = get_u_int32_t(packet->payload, 2);
	flow->l4.udp.battlefield_stage = 1 + packet->packet_direction;
	return;
      }
    } else if (flow->l4.udp.battlefield_stage == 2 - packet->packet_direction) {
      if (packet->payload_packet_len > 8 && get_u_int32_t(packet->payload, 0) == flow->l4.udp.battlefield_msg_id) {
	NDPI_LOG(NDPI_PROTOCOL_BATTLEFIELD, ndpi_struct,
		 NDPI_LOG_DEBUG, "Battlefield message and reply detected.\n");
	ndpi_int_battlefield_add_connection(ndpi_struct, flow);
	return;
      }
    }
  }

  if (flow->l4.udp.battlefield_stage == 0) {
    if (packet->payload_packet_len == 46 && packet->payload[2] == 0 && packet->payload[4] == 0
	&& get_u_int32_t(packet->payload, 7) == htonl(0x98001100)) {
      flow->l4.udp.battlefield_stage = 3 + packet->packet_direction;
      return;
    }
  } else if (flow->l4.udp.battlefield_stage == 4 - packet->packet_direction) {
    if (packet->payload_packet_len == 7
	&& (packet->payload[0] == 0x02 || packet->payload[packet->payload_packet_len - 1] == 0xe0)) {
      NDPI_LOG(NDPI_PROTOCOL_BATTLEFIELD, ndpi_struct, NDPI_LOG_DEBUG,
	       "Battlefield message and reply detected.\n");
      ndpi_int_battlefield_add_connection(ndpi_struct, flow);
      return;
    }
  }

  if (packet->payload_packet_len == 18 && memcmp(&packet->payload[5], "battlefield2\x00", 13) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_BATTLEFIELD, ndpi_struct, NDPI_LOG_DEBUG, "Battlefield 2 hello packet detected.\n");
    ndpi_int_battlefield_add_connection(ndpi_struct, flow);
    return;
  } else if (packet->payload_packet_len > 10 &&
	     (memcmp(packet->payload, "\x11\x20\x00\x01\x00\x00\x50\xb9\x10\x11", 10) == 0
	      || memcmp(packet->payload, "\x11\x20\x00\x01\x00\x00\x30\xb9\x10\x11", 10) == 0
	      || memcmp(packet->payload, "\x11\x20\x00\x01\x00\x00\xa0\x98\x00\x11", 10) == 0)) {
    NDPI_LOG(NDPI_PROTOCOL_BATTLEFIELD, ndpi_struct, NDPI_LOG_DEBUG, "Battlefield safe pattern detected.\n");
    ndpi_int_battlefield_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_BATTLEFIELD);
  return;
}

#endif
