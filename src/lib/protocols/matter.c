/*
 * matter.c
 *
 * Copyright (C) 2025 - ntop.org
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
 *
 */


#include "ndpi_protocol_ids.h"
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MATTER
#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_matter(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Matter\n");

  if(packet->udp) {
    u_int16_t sport = ntohs(packet->udp->source);
    u_int16_t dport = ntohs(packet->udp->dest);

    /* Matter typically uses UDP ports 5540 (operational), 5542 (commissioning) */
    if(!(sport == 5540 || dport == 5540 || sport == 5542 || dport == 5542)) {
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
      return;
    }

    { 
      /* Matter messages usually have at least a 16-byte header (secure session framing) */
      if(packet->payload_packet_len >= 16) {
        uint8_t message_flags, version, dsiz, security_flags;

        message_flags = packet->payload[0];
        version = (message_flags >> 4) & 0x0F;
        dsiz = message_flags & 0x03;
        security_flags = packet->payload[3];
        uint8_t session_type = security_flags & 0x03;

        /* https://csa-iot.org/wp-content/uploads/2024/11/24-27349-006_Matter-1.4-Core-Specification.pdf 4.4.1 */
        /* TODO: quite weak...*/
        if(version <= 1 &&
           (message_flags & 0x08) == 0 /* Reserved bit */ &&
           dsiz <= 2 &&
           (security_flags & 0x1C) == 0 /* Reserved bits */ &&
            session_type <= 2) {

          uint16_t session_id = ntohs(*(uint16_t *)&packet->payload[1]);
          
          if((session_type == 0 && session_id != 0) ||  
             (session_type > 0 && session_id == 0)) {   
            NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);   
            return;                                       
          } 
                            
          NDPI_LOG_INFO(ndpi_struct, "Found Matter\n");
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MATTER,
                                     NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
          return;
        }
      }
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_matter_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("Matter", ndpi_struct,
                     ndpi_search_matter,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP_WITH_PAYLOAD, /* MATTER is only over IPv6 */
                     1, NDPI_PROTOCOL_MATTER);
}
