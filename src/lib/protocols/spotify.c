/*
 * spotify.c
 *
 * Copyright (C) 2011-18 by ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SPOTIFY

#include "ndpi_api.h"


static void ndpi_int_spotify_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					    u_int8_t due_to_correlation)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SPOTIFY, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}


static void ndpi_check_spotify(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  if(packet->udp != NULL) {
    u_int16_t spotify_port = htons(57621);

    if((packet->udp->source == spotify_port)
       && (packet->udp->dest == spotify_port)) {
      if(payload_len >= 7) {
	if(memcmp(packet->payload, "SpotUdp", 7) == 0) {
	  NDPI_LOG_INFO(ndpi_struct, "found spotify udp dissector\n");
	  ndpi_int_spotify_add_connection(ndpi_struct, flow, 0);
	  return;
	}
      }
    }
  } else if(packet->tcp != NULL) {

    if(payload_len >= 9 && packet->payload[0] == 0x00 && packet->payload[1] == 0x04 &&
       packet->payload[2] == 0x00 && packet->payload[3] == 0x00&&
       packet->payload[6] == 0x52 && (packet->payload[7] == 0x0e || packet->payload[7] == 0x0f) &&
       packet->payload[8] == 0x50 ) {
      NDPI_LOG_INFO(ndpi_struct, "found spotify tcp dissector\n");
      ndpi_int_spotify_add_connection(ndpi_struct, flow, 0);
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

static void ndpi_search_spotify(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_DBG(ndpi_struct, "search spotify\n");

  /* skip marked packets */
  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_SPOTIFY) {
    ndpi_check_spotify(ndpi_struct, flow);
  }
}


void init_spotify_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("SPOTIFY", ndpi_struct, *id,
				      NDPI_PROTOCOL_SPOTIFY,
				      ndpi_search_spotify,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

