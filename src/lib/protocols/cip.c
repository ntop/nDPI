/*
 * cip.c
 *
 * Copyright (C) 2018-24 - ntop.org
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

/* https://en.wikipedia.org/wiki/Common_Industrial_Protocol */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CIP

#define CIP_IO_PORT  2222

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_cip(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search cip\n");

  if(packet->udp
     && (ntohs(packet->udp->source) == CIP_IO_PORT) && (ntohs(packet->udp->dest) == CIP_IO_PORT)
     && (packet->payload_packet_len >= 12)
     && (packet->payload_packet_len < 64)
     && (packet->payload[1] == 0x0)
     ) {
    u_int8_t num_items = packet->payload[0], offset = 2;

    while((num_items > 0) && (packet->payload_packet_len > ((u_int32_t)offset + 4))) {
      // u_int16_t type_id = *((u_int16_t*)&packet->payload[offset]);
      u_int16_t lenght = (packet->payload[offset+3] << 8) + packet->payload[offset+2];

      offset += 4 + lenght;
      num_items--;
    }

    if(offset == packet->payload_packet_len) {
      NDPI_LOG_INFO(ndpi_struct,"found cip\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CIP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    }
  } else {
    /* TODO add TCP dissection */
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_cip_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("CIP", ndpi_struct, *id,
				      NDPI_PROTOCOL_CIP,
				      ndpi_search_cip,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
