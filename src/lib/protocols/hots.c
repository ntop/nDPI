/*
 * hots.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HOTS

#include "ndpi_api.h"

static void ndpi_hots_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HOTS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  NDPI_LOG_INFO(ndpi_struct, "found \"Heroes of the Storm\" packet\n");
}

void ndpi_search_hots(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search \"Heroes of the Storm\"\n");

  if (packet->udp != NULL) {
    if (packet->udp->dest == ntohs(3724) || packet->udp->source == ntohs(3724)) {
      if (packet->payload_packet_len >= 20 && packet->payload_packet_len <= 122) {
        if (packet->payload[14] == 0x40 && packet->payload[15] == 0x00) {
          if ((packet->payload[2] == 0x03 && packet->payload[3] == 0x00) ||
              (packet->payload[2] == 0x34 && packet->payload[3] == 0x00) ||
              (packet->payload[0] == 0x00 && packet->payload[1] == 0x00 && packet->payload[2] == 0x00 &&
               packet->payload[3] == 0x00 && packet->payload[4] == 0x00 && packet->payload[5] == 0x00 &&
               packet->payload[6] == 0x00 && packet->payload[7] == 0x00 && packet->payload[8] == 0x00 &&
               packet->payload[9] == 0x00 && packet->payload[10] == 0x00 && packet->payload[11] == 0x00 &&
               packet->payload[12] == 0x00 && packet->payload[13] == 0x00)) {
                 NDPI_LOG_INFO(ndpi_struct, "found \"Heroes of the Storm\"\n");
                 ndpi_hots_add_connection(ndpi_struct, flow);
                 return;
          }
        }
      }
    }
  }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_hots_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("HOTS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_HOTS,
				      ndpi_search_hots,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}