/*
 * upnp.c
 *
 * Copyright (C) 2018 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UPNP

#include "ndpi_api.h"

#define UPNP_PORT 3702

void ndpi_search_upnp(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search upnp\n");

  if(packet->udp
     && (
	 (packet->iph && ((ntohl(packet->iph->daddr) & 0xF0000000) == 0xE0000000 /* A multicast address */))
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	 ||
	 (packet->iphv6 && ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0]) == 0xFF020000)
#endif
	 )
     && (ntohs(packet->udp->dest) == UPNP_PORT)
     && (packet->payload_packet_len >= 40)
     && (strncmp((char*)packet->payload, "<?xml", 5) == 0)
     ) {
    NDPI_LOG_INFO(ndpi_struct,"found teredo\n");
    ndpi_int_change_protocol(ndpi_struct, flow, NDPI_PROTOCOL_UPNP, NDPI_PROTOCOL_UNKNOWN);
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}


void init_upnp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("UPNP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_UPNP,
				      ndpi_search_upnp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

