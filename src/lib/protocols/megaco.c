/*
 * megaco.c 
 *
 * Copyright (C) 2014 by Gianluca Costa http://www.capanalysis.net
 * Copyright (C) 2012-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MEGACO

#include "ndpi_api.h"


void ndpi_search_megaco(struct ndpi_detection_module_struct *ndpi_struct,
			struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  NDPI_LOG_DBG(ndpi_struct, "search for MEGACO\n");
  
  if(packet->udp != NULL) {
    if((packet->payload_packet_len > 4 && packet->payload[0] == '!' && packet->payload[1] == '/' &&
        packet->payload[2] == '1' && packet->payload[3] == ' ' && packet->payload[4] == '[')
       || (packet->payload_packet_len > 9 && packet->payload[0] == 'M' && packet->payload[1] == 'E' &&
        packet->payload[2] == 'G' && packet->payload[3] == 'A' && packet->payload[4] == 'C' &&
        packet->payload[5] == 'O' && packet->payload[6] == '/' &&
        packet->payload[7] == '1' && packet->payload[8] == ' ' && packet->payload[9] == '[')) {
      NDPI_LOG_INFO(ndpi_struct, "found MEGACO\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MEGACO, NDPI_PROTOCOL_UNKNOWN);
      return;
    } 
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_megaco_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Megaco", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MEGACO,
				      ndpi_search_megaco,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
