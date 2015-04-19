/*
 * iax.c
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
#ifdef NDPI_PROTOCOL_IAX

#define NDPI_IAX_MAX_INFORMATION_ELEMENTS 15

static void ndpi_int_iax_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_IAX, NDPI_REAL_PROTOCOL);
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
      NDPI_LOG(NDPI_PROTOCOL_IAX, ndpi_struct, NDPI_LOG_DEBUG, "found IAX.\n");
      ndpi_int_iax_add_connection(ndpi_struct, flow);
      return;
    }
    packet_len = 12;
    for (i = 0; i < NDPI_IAX_MAX_INFORMATION_ELEMENTS; i++) {
      packet_len = packet_len + 2 + packet->payload[packet_len + 1];
      if (packet_len == packet->payload_packet_len) {
	NDPI_LOG(NDPI_PROTOCOL_IAX, ndpi_struct, NDPI_LOG_DEBUG, "found IAX.\n");
	ndpi_int_iax_add_connection(ndpi_struct, flow);
	return;
      }
      if (packet_len > packet->payload_packet_len) {
	break;
      }
    }

  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_IAX);

}

void ndpi_search_iax(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  //      struct ndpi_flow_struct       *flow=ndpi_struct->flow;
  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  if(packet->udp 
     && (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN))
    ndpi_search_setup_iax(ndpi_struct, flow);
}
#endif
