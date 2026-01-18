/*
 * wsd.c
 *
 * Copyright (C) 2018-22 - ntop.org
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

/* https://en.wikipedia.org/wiki/WS-Discovery */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WSD

#include "ndpi_api.h"
#include "ndpi_private.h"

#define WSD_PORT 3702

static void ndpi_search_wsd(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search wsd\n");

  if(packet->udp
     && (
	 (packet->iph && ((ntohl(packet->iph->daddr) & 0xF0000000) == 0xE0000000 /* A multicast address */))
	 ||
	 (packet->iphv6 && ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0]) == 0xFF020000)
	 )
     && (ntohs(packet->udp->dest) == WSD_PORT)
     && (packet->payload_packet_len >= 40)
     && (strncmp((char*)packet->payload, "<?xml", 5) == 0)
     ) {
    NDPI_LOG_INFO(ndpi_struct,"found wsd\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WSD, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  } else {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  }
}


void init_wsd_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("WSD", ndpi_struct,
                     ndpi_search_wsd,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                     1, NDPI_PROTOCOL_WSD);
}

