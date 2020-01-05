/*
 * eaq.c
 *
 * Copyright (C) 2015-20 - ntop.org
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


/*
  EAQ: Entitade Aferidora da Qualidade de Banda Larga

  http://www.brasilbandalarga.com.br
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_EAQ

#include "ndpi_api.h"

#define EAQ_DEFAULT_PORT   6000
#define EAQ_DEFAULT_SIZE     16

static void ndpi_int_eaq_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_EAQ, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_eaq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  if (!flow) {
    return;
  }

  struct ndpi_packet_struct *packet = &flow->packet;
  if (!packet) {
    return;
  }

  u_int16_t sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
  
  NDPI_LOG_DBG(ndpi_struct, "search eaq\n");

  do {
    if( (packet->payload_packet_len != EAQ_DEFAULT_SIZE) ||
        ((sport != EAQ_DEFAULT_PORT) && (dport != EAQ_DEFAULT_PORT)) )
	    break;
      
    if(packet->udp != NULL) {
      u_int32_t seq = (packet->payload[0] * 1000) + (packet->payload[1] * 100) + (packet->payload[2] * 10) + packet->payload[3];

      if(flow->l4.udp.eaq_pkt_id == 0)
        flow->l4.udp.eaq_sequence = seq;
      else {
        if( (flow->l4.udp.eaq_sequence != seq) &&
	    ((flow->l4.udp.eaq_sequence+1) != seq))
	  break;
	else
	  flow->l4.udp.eaq_sequence = seq;
      }

      if(++flow->l4.udp.eaq_pkt_id == 4) {
        /* We have collected enough packets so we assume it's EAQ */
        NDPI_LOG_INFO(ndpi_struct, "found eaq\n");
        ndpi_int_eaq_add_connection(ndpi_struct, flow);
        return;
      } else
	return;
    }
  } while(0);

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

}


void init_eaq_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("EAQ", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_EAQ,
				      ndpi_search_eaq,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
