/*
 * dhcp.c
 *
 * Copyright (C) 2016 - ntop.org
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


#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_DHCP

static void ndpi_int_dhcp_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DHCP, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_dhcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	
  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  /* this detection also works for asymmetric dhcp traffic */

  /*check standard DHCP 0.0.0.0:68 -> 255.255.255.255:67 */
  if(packet->udp) {
    if(packet->payload_packet_len >= 244 &&
       (packet->udp->source == htons(67) || packet->udp->source == htons(68)) &&
       (packet->udp->dest == htons(67) || packet->udp->dest == htons(68)) &&
       get_u_int32_t(packet->payload, 236) == htonl(0x63825363) &&
       get_u_int16_t(packet->payload, 240) == htons(0x3501)) {
      
      NDPI_LOG(NDPI_PROTOCOL_DHCP, ndpi_struct, NDPI_LOG_DEBUG, "DHCP request\n");
      
      ndpi_int_dhcp_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DHCP);
}


void init_dhcp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("DHCP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DHCP,
				      ndpi_search_dhcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

#endif
