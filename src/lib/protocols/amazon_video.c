/*
 * amazon_video.c
 *
 * Copyright (C) 2018-20 by ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_AMAZON_VIDEO

#include "ndpi_api.h"

static void ndpi_check_amazon_video(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Amazon Prime\n");

  if(packet->payload_packet_len > 4) {
    if((packet->tcp != NULL) &&
       (packet->payload[0] == 0xFE &&
	packet->payload[1] == 0xED &&
	packet->payload[2] == 0xFA &&
	packet->payload[3] == 0xCE)) {
      NDPI_LOG_INFO(ndpi_struct, "found Amazon Video on TCP\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_AMAZON_VIDEO, NDPI_PROTOCOL_UNKNOWN);
      return;
    } else if((packet->udp != NULL) &&
	      (packet->payload[0] == 0xDE &&
	       packet->payload[1] == 0xAD &&
	       packet->payload[2] == 0xBE &&
	       packet->payload[3] == 0xEF)) {
      NDPI_LOG_INFO(ndpi_struct, "found Amazon Video on UDP\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_AMAZON_VIDEO, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void ndpi_search_amazon_video(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search amazon_video\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_AMAZON_VIDEO)
    ndpi_check_amazon_video(ndpi_struct, flow);
}


void init_amazon_video_dissector(struct ndpi_detection_module_struct *ndpi_struct,
				 u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("AMAZON_VIDEO", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_AMAZON_VIDEO,
				      ndpi_search_amazon_video,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
