/*
 * afp.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-16 - ntop.org
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
 * 
 */

#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_AFP

struct afpHeader {
  u_int8_t flags, command;
  u_int16_t requestId;
  u_int32_t dataOffset, length, reserved;
};

static void ndpi_int_afp_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_AFP, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_afp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if (packet->payload_packet_len >= sizeof(struct afpHeader)) {
    struct afpHeader *h = (struct afpHeader*)packet->payload;

    if(packet->payload_packet_len > 128) {
      /*
	When we transfer a large data chunk, unless we have observed
	the initial connection, we need to discard these packets
	as they are not an indication that this flow is not AFP	
      */
      return;
    }

    /*
     * this will detect the OpenSession command of the Data Stream Interface (DSI) protocol
     * which is exclusively used by the Apple Filing Protocol (AFP) on TCP/IP networks
     */
    if (packet->payload_packet_len >= 22 && get_u_int16_t(packet->payload, 0) == htons(0x0004) &&
	get_u_int16_t(packet->payload, 2) == htons(0x0001) && get_u_int32_t(packet->payload, 4) == 0 &&
	get_u_int32_t(packet->payload, 8) == htonl(packet->payload_packet_len - 16) &&
	get_u_int32_t(packet->payload, 12) == 0 && get_u_int16_t(packet->payload, 16) == htons(0x0104)) {

      NDPI_LOG(NDPI_PROTOCOL_AFP, ndpi_struct, NDPI_LOG_DEBUG, "AFP: DSI OpenSession detected.\n");
      ndpi_int_afp_add_connection(ndpi_struct, flow);
      return;
    }

    if((h->flags <= 1)
       && ((h->command >= 1) && (h->command <= 8))
       && (h->reserved == 0)
       && (packet->payload_packet_len >= (sizeof(struct afpHeader)+ntohl(h->length)))) {
      NDPI_LOG(NDPI_PROTOCOL_AFP, ndpi_struct, NDPI_LOG_DEBUG, "AFP: DSI detected.\n");
      ndpi_int_afp_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_LOG(NDPI_PROTOCOL_AFP, ndpi_struct, NDPI_LOG_DEBUG, "AFP excluded.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_AFP);
}


void init_afp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("AFP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_AFP,
				      ndpi_search_afp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}


#endif
