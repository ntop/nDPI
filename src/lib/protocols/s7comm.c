/*
 * s7comm.c
 *
 * Copyright (C) 2011-21 - ntop.org
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
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_S7COMM
#include "ndpi_api.h"

void ndpi_search_s7comm_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  NDPI_LOG_DBG(ndpi_struct, "search S7\n");
  u_int16_t s7comm_port = htons(102); 
  if(packet->tcp) {
    
    if((packet->payload_packet_len >= 2) && (packet->payload[0]==0x03)&&(packet->payload[1]==0x00)&&((packet->tcp->dest == s7comm_port) || (packet->tcp->source == s7comm_port))) {
      NDPI_LOG_INFO(ndpi_struct, "found S7\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_S7COMM, NDPI_PROTOCOL_UNKNOWN);

      return;
      
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
   
}

void init_s7comm_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
      
  ndpi_set_bitmask_protocol_detection("S7COMM", ndpi_struct, detection_bitmask, *id,
                              NDPI_PROTOCOL_S7COMM,
                              ndpi_search_s7comm_tcp,                            NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                              SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                              ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

