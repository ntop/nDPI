/*
 * ayiya.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

/*
  https://www.cisco.com/c/en/us/support/docs/ip/hot-standby-router-protocol-hsrp/9234-hsrpguidetoc.html
*/

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HSRP

#include "ndpi_api.h"

#define HSRP_PORT	1985
#define HSRP_PORT_V6	2029

static void ndpi_search_hsrp(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t port_to_match;

  NDPI_LOG_DBG(ndpi_struct, "search HSRP\n");

  if(packet->iphv6) {
    port_to_match = htons(HSRP_PORT_V6);

    if((packet->udp->source == port_to_match) && (packet->udp->dest == port_to_match)
       && (packet->payload[0] <= 0x04) /* Message type */
       && (ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0]) == 0xFF020000)
       && (ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[1]) == 0x00000000)
       && (ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[2]) == 0x00000000)
       && (ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[3]) == 0x00000066)) { /* multicast: ff02::66 */;
      NDPI_LOG_INFO(ndpi_struct, "found HSRP\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HSRP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  } else if(packet->iph) {
    port_to_match = htons(HSRP_PORT);

    if((packet->udp->source == port_to_match) && (packet->udp->dest == port_to_match)) {
      u_int8_t found = 0;
      
      if((ntohl(packet->iph->daddr) == 0xE0000002 /* 224.0.0.2 v0 */)
	 && (packet->payload_packet_len >= 20)
	 && (packet->payload[0] == 0x0 /* v0 */)
	 && (packet->payload[7] == 0x0 /* reserved */))
	found = 1; /* v0 */
      else if((packet->payload_packet_len >= 42)
	      && (packet->payload[2] == 0x02) /* Version 2 */
	      && (packet->payload[5] == 0x04) /* IPv4      */
	      && (ntohl(packet->iph->daddr) == 0xE0000066 /* 224.0.0.102 v2 */))
	found = 1;

      if(found) {
	NDPI_LOG_INFO(ndpi_struct, "found HSRP\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HSRP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
	return;
      }
    }
  }
  
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_hsrp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			 u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("HSRP", ndpi_struct, *id,
				      NDPI_PROTOCOL_HSRP,
				      ndpi_search_hsrp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
