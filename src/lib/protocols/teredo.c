/*
 * teredo.c
 *
 * Copyright (C) 2015-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TEREDO

#include "ndpi_api.h"

/* https://en.wikipedia.org/wiki/Teredo_tunneling */
void ndpi_search_teredo(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct,"search teredo\n");
  if(packet->udp
     && packet->iph
     && ((ntohl(packet->iph->daddr) & 0xF0000000) != 0xE0000000 /* Not a multicast address */)
     && ((ntohs(packet->udp->source) == 3544) || (ntohs(packet->udp->dest) == 3544))
     && (packet->payload_packet_len >= 40 /* IPv6 header */)) {
    NDPI_LOG_INFO(ndpi_struct,"found teredo\n");
    ndpi_int_change_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TEREDO, NDPI_PROTOCOL_UNKNOWN);
  }  else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}


void init_teredo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("TEREDO", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_TEREDO,
				      ndpi_search_teredo,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

