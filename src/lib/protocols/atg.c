/*
 * atg.c
 *
 * Copyright (C) 2024 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ATG

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_atg_add_connection(struct ndpi_detection_module_struct
						*ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ATG,
			     NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}


static void ndpi_search_atg(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search for ATG\n");

  if(packet->payload_packet_len >= 8) {
    u_int16_t atg_port = ntohs(10001);

    if((packet->tcp->source == atg_port) || (packet->tcp->dest == atg_port)) {
      if(packet->payload[0] == 0x01 &&
         (packet->payload[1] == 0x49 || packet->payload[1] == 0x69 || packet->payload[1] == 0x53 || packet->payload[1] == 0x73 ) &&
         memcmp(&packet->payload[packet->payload_packet_len - 2], "\r\n", 2) == 0) {
        NDPI_LOG_INFO(ndpi_struct, "found atg\n");
        ndpi_int_atg_add_connection(ndpi_struct, flow);
        return;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_atg_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                        u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("ATG", ndpi_struct, *id,
				      NDPI_PROTOCOL_ATG,
				      ndpi_search_atg,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
