/*
 * viber.c 
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 * Copyright (C) 2013-18 - ntop.org
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_VIBER

#include "ndpi_api.h"


void ndpi_search_viber(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  NDPI_LOG_DBG(ndpi_struct, "search for VIBER\n");
  
  if((packet->udp != NULL) && (packet->payload_packet_len > 5)) {
    NDPI_LOG_DBG2(ndpi_struct, "calculating dport over udp\n");

    if((packet->payload[2] == 0x03 && packet->payload[3] == 0x00)
       || (packet->payload_packet_len == 20 && packet->payload[2] == 0x09 && packet->payload[3] == 0x00)
       || (packet->payload[2] == 0x01 && packet->payload[3] == 0x00 && packet->payload[4] == 0x05 && packet->payload[5] == 0x00)
       || (packet->payload_packet_len == 34 && packet->payload[2] == 0x19 && packet->payload[3] == 0x00)
       || (packet->payload_packet_len == 34 && packet->payload[2] == 0x1b && packet->payload[3] == 0x00)
       ) {
      NDPI_LOG_DBG(ndpi_struct, "found VIBER\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_VIBER, NDPI_PROTOCOL_UNKNOWN);
      return;
    } 
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_viber_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) 
{
  ndpi_set_bitmask_protocol_detection("VIBER", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_VIBER,
				      ndpi_search_viber,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

