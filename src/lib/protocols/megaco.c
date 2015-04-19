/*
 * megaco.c 
 *
 * Copyright (C) 2014 by Gianluca Costa http://www.capanalysis.net
 * Copyright (C) 2012-15 - ntop.org
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


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_MEGACO

void ndpi_search_megaco(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  NDPI_LOG(NDPI_PROTOCOL_MEGACO, ndpi_struct, NDPI_LOG_DEBUG, "search for MEGACO.\n");
  
  if(packet->udp != NULL) {
    if((packet->payload_packet_len > 4 && packet->payload[0] == '!' && packet->payload[1] == '/' &&
        packet->payload[2] == '1' && packet->payload[3] == ' ' && packet->payload[4] == '[')
       || (packet->payload_packet_len > 9 && packet->payload[0] == 'M' && packet->payload[1] == 'E' &&
        packet->payload[2] == 'G' && packet->payload[3] == 'A' && packet->payload[4] == 'C' &&
        packet->payload[5] == 'O' && packet->payload[6] == '/' &&
        packet->payload[7] == '1' && packet->payload[8] == ' ' && packet->payload[9] == '[')) {
      NDPI_LOG(NDPI_PROTOCOL_MEGACO, ndpi_struct, NDPI_LOG_DEBUG, "found MEGACO.\n");
      ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MEGACO, NDPI_REAL_PROTOCOL);
      return;
    } 
  }

  NDPI_LOG(NDPI_PROTOCOL_MEGACO, ndpi_struct, NDPI_LOG_DEBUG, "exclude MEGACO.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MEGACO);
}

#endif
