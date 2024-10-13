/*
 * sonos.c
 *
 * Copyright (C) 2024 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SONOS

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_sonos_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SONOS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  NDPI_LOG_INFO(ndpi_struct, "Found Sonos flow\n");
}

void ndpi_search_sonos(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "Searching Sonos\n");

  if((!ndpi_is_public_ipv4(ntohl(packet->iph->daddr)))
     && ((ntohl(packet->iph->daddr) & 0xF0000000) != 0xE0000000 /* Not a multicast address */)) {  
    if(packet->payload_packet_len == 48) {      
      u_int16_t sonos_port = htons(12301);
      
      if((packet->udp->dest == sonos_port) || (packet->udp->source == sonos_port)) {	
	ndpi_sonos_add_connection(ndpi_struct, flow);
      }
    } else {
      u_int16_t sonos_port = htons(7080);
      
      if((packet->udp->dest == sonos_port)
	 && ((packet->payload_packet_len < 200)
	     || ((packet->payload_packet_len > 1000) && (packet->payload_packet_len < 1100)))) {
	ndpi_sonos_add_connection(ndpi_struct, flow);
      }
    }
  }
  
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_sonos_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Sonos", ndpi_struct, *id,
				      NDPI_PROTOCOL_SONOS,
				      ndpi_search_sonos,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, /* Only IPv4 UDP traffic is expected. */
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
