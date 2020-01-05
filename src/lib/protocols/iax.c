/*
 * iax.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_IAX

#include "ndpi_api.h"


#define NDPI_IAX_MAX_INFORMATION_ELEMENTS 15

static void ndpi_int_iax_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_IAX, NDPI_PROTOCOL_UNKNOWN);
}

static void ndpi_search_setup_iax(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t i;
  u_int16_t packet_len;

  if (						/* 1. iax is udp based, port 4569 */
      (packet->udp->source == htons(4569) || packet->udp->dest == htons(4569))
      /* check for iax new packet */
      && packet->payload_packet_len >= 12
      /* check for dst call id == 0, do not check for highest bit (packet retransmission) */
      // && (ntohs(get_u_int16_t(packet->payload, 2)) & 0x7FFF) == 0
      /* check full IAX packet  */
      && (packet->payload[0] & 0x80) != 0
      /* outbound seq == 0 */
      && packet->payload[8] == 0
      /* inbound seq == 0 || 1  */
      && (packet->payload[9] == 0 || packet->payload[9] == 0x01)
      /*  */
      && packet->payload[10] == 0x06
      /* IAX type: 0-15 */
      && packet->payload[11] <= 15) {

    if (packet->payload_packet_len == 12) {
      NDPI_LOG_INFO(ndpi_struct, "found IAX\n");
      ndpi_int_iax_add_connection(ndpi_struct, flow);
      return;
    }
    packet_len = 12;
    for (i = 0; i < NDPI_IAX_MAX_INFORMATION_ELEMENTS; i++) {
      packet_len = packet_len + 2 + packet->payload[packet_len + 1];
      if (packet_len == packet->payload_packet_len) {
	NDPI_LOG_INFO(ndpi_struct, "found IAX\n");
	ndpi_int_iax_add_connection(ndpi_struct, flow);
	return;
      }
      if (packet_len > packet->payload_packet_len) {
	break;
      }
    }

  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

}

void ndpi_search_iax(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->udp 
     && (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN))
    ndpi_search_setup_iax(ndpi_struct, flow);
}


void init_iax_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("IAX", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IAX,
				      ndpi_search_iax,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
