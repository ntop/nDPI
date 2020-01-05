/*
 * battlefield.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_BATTLEFIELD

#include "ndpi_api.h"

static void ndpi_int_battlefield_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BATTLEFIELD, NDPI_PROTOCOL_UNKNOWN);

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
      NDPI_LOG_DBG2(ndpi_struct,
	       "battlefield : save src connection packet detected\n");
      src->battlefield_ts = packet->tick_timestamp;
    } else if (dst != NULL && ((u_int32_t)
			       (packet->tick_timestamp - dst->battlefield_ts) < ndpi_struct->battlefield_timeout)) {
      NDPI_LOG_DBG2(ndpi_struct,
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
	NDPI_LOG_INFO(ndpi_struct, "found Battlefield message and reply detected\n");
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
      NDPI_LOG_INFO(ndpi_struct, "found Battlefield message and reply detected\n");
      ndpi_int_battlefield_add_connection(ndpi_struct, flow);
      return;
    }
  }

  if (packet->payload_packet_len == 18 && memcmp(&packet->payload[5], "battlefield2\x00", 13) == 0) {
    NDPI_LOG_INFO(ndpi_struct, "found Battlefield 2 hello packet detected\n");
    ndpi_int_battlefield_add_connection(ndpi_struct, flow);
    return;
  } else if (packet->payload_packet_len > 10 &&
	     (memcmp(packet->payload, "\x11\x20\x00\x01\x00\x00\x50\xb9\x10\x11", 10) == 0
	      || memcmp(packet->payload, "\x11\x20\x00\x01\x00\x00\x30\xb9\x10\x11", 10) == 0
	      || memcmp(packet->payload, "\x11\x20\x00\x01\x00\x00\xa0\x98\x00\x11", 10) == 0)) {
    NDPI_LOG_INFO(ndpi_struct, "found Battlefield safe pattern detected\n");
    ndpi_int_battlefield_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_battlefield_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("BattleField", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_BATTLEFIELD,
				      ndpi_search_battlefield,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
