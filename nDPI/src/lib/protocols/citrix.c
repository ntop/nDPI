/*
 * citrix.c
 *
 * Copyright (C) 2012-15 - ntop.org
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


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_CITRIX

/* ************************************ */

static void ndpi_check_citrix(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  if(packet->tcp != NULL) {
    flow->l4.tcp.citrix_packet_id++;
    
    if((flow->l4.tcp.citrix_packet_id == 3)
       /* We have seen the 3-way handshake */
       && flow->l4.tcp.seen_syn
       && flow->l4.tcp.seen_syn_ack
       && flow->l4.tcp.seen_ack) {
      if(payload_len == 6) {
	char citrix_header[] = { 0x07, 0x07, 0x49, 0x43, 0x41, 0x00 };
	
	if(memcmp(packet->payload, citrix_header, sizeof(citrix_header)) == 0) {
	  NDPI_LOG(NDPI_PROTOCOL_CITRIX, ndpi_struct, NDPI_LOG_DEBUG, "Found citrix.\n");
	  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CITRIX, NDPI_PROTOCOL_UNKNOWN);
	}

	return;
      } else if(payload_len > 4) {
	char citrix_header[] = { 0x1a, 0x43, 0x47, 0x50, 0x2f, 0x30, 0x31 };
	
	if((memcmp(packet->payload, citrix_header, sizeof(citrix_header)) == 0)
	   || (ndpi_strnstr((const char *)packet->payload, "Citrix.TcpProxyService", payload_len) != NULL)) {
	  NDPI_LOG(NDPI_PROTOCOL_CITRIX, ndpi_struct, NDPI_LOG_DEBUG, "Found citrix.\n");
	  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CITRIX, NDPI_PROTOCOL_UNKNOWN);
	}

	return;	
      }
      
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_CITRIX);
    } else if(flow->l4.tcp.citrix_packet_id > 3)
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_CITRIX);
    
    return;
  }
}

void ndpi_search_citrix(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_CITRIX, ndpi_struct, NDPI_LOG_DEBUG, "citrix detection...\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_CITRIX)
    ndpi_check_citrix(ndpi_struct, flow);
}


void init_citrix_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Citrix", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_CITRIX,
				      ndpi_search_citrix,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

#endif
