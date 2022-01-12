/*
 * zmq.c
 *
 * Copyright (C) 2016-22 - ntop.org
 *
 * nDPI is free software: you can zmqtribute it and/or modify
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ETHERNET_IP

#include "ndpi_api.h"

static void ndpi_int_ethernet_ip_add_connection(struct ndpi_detection_module_struct
						*ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ETHERNET_IP,
			     NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}


void ndpi_search_ethernet_ip(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  
  NDPI_LOG_DBG(ndpi_struct, "search for ETHERNET_IP\n");

  if(packet->tcp != NULL) {
    NDPI_LOG_DBG2(ndpi_struct, "calculating ETHERNET_IP over tcp\n");
  
    if(packet->payload_packet_len >= 24) {
      u_int16_t eth_ip_port = ntohs(44818);

      if((packet->tcp->source == eth_ip_port) || (packet->tcp->dest == eth_ip_port)) {
	u_int16_t len = *((u_int16_t*)&packet->payload[2]); /* Little endian */
	
	if((len+24) == packet->payload_packet_len) {	
	  NDPI_LOG_INFO(ndpi_struct, "found ethernet_ip\n");
	  ndpi_int_ethernet_ip_add_connection(ndpi_struct, flow);
	  return;
	}
      }
    }
  }
  
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow); /* No luck this time */
}
  

void init_ethernet_ip_dissector(struct ndpi_detection_module_struct *ndpi_struct,
				u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("EthernetIP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_ETHERNET_IP,
				      ndpi_search_ethernet_ip,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
