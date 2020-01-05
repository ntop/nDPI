/*
 * bgp.c
 *
 * Copyright (C) 2016-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_BGP

#include "ndpi_api.h"


/* this detection also works asymmetrically */
void ndpi_search_bgp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t bgp_port = htons(179);

  NDPI_LOG_DBG(ndpi_struct, "search BGP\n");

  if(packet->tcp) {
    if(packet->payload_packet_len > 18
       && packet->payload[18] < 5
       && ((packet->tcp->dest == bgp_port) || (packet->tcp->source == bgp_port))
       && (get_u_int64_t(packet->payload, 0) == 0xffffffffffffffffULL)
       && (get_u_int64_t(packet->payload, 8) == 0xffffffffffffffffULL)
       && (ntohs(get_u_int16_t(packet->payload, 16)) <= packet->payload_packet_len)) {
      
      NDPI_LOG_INFO(ndpi_struct, "found BGP\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BGP, NDPI_PROTOCOL_UNKNOWN);
      return;
    } 
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_bgp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("BGP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_BGP,
				      ndpi_search_bgp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

