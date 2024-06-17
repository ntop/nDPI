/*
 * afp.c
 *
 * Copyright (C) 2009-11 by ipoque GmbH
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
 * 
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_AFP

#include "ndpi_api.h"
#include "ndpi_private.h"

struct afpHeader {
  u_int8_t flags, command;
  u_int16_t requestId;
  u_int32_t dataOffset, length, reserved;
};

static void ndpi_int_afp_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_AFP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}


static void ndpi_search_afp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search AFP\n");

  if (packet->payload_packet_len >= sizeof(struct afpHeader)) {
    struct afpHeader *h = (struct afpHeader*)packet->payload;

    if(packet->payload_packet_len > 128) {
      /*
	When we transfer a large data chunk, unless we have observed
	the initial connection, we need to discard these packets
	as they are not an indication that this flow is not AFP	
      */
      if(flow->packet_counter > 5)
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    if((h->flags <= 1)
       && ((h->command >= 1) && (h->command <= 8))
       && (h->reserved == 0)
       && (packet->payload_packet_len >= (sizeof(struct afpHeader)+ntohl(h->length)))) {
      NDPI_LOG_INFO(ndpi_struct, "found AFP: DSI\n");
      ndpi_int_afp_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_afp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("AFP", ndpi_struct, *id,
				      NDPI_PROTOCOL_AFP,
				      ndpi_search_afp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

