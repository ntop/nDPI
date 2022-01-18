/*
 * rdp.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RDP

#define RDP_PORT 3389

#include "ndpi_api.h"

static void ndpi_int_rdp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RDP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

void ndpi_search_rdp(struct ndpi_detection_module_struct *ndpi_struct,
		     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
	
  NDPI_LOG_DBG(ndpi_struct, "search RDP\n");

  if (packet->tcp != NULL) {
    if (packet->payload_packet_len > 10
	&& get_u_int8_t(packet->payload, 0) > 0
	&& get_u_int8_t(packet->payload, 0) < 4 && get_u_int16_t(packet->payload, 2) == ntohs(packet->payload_packet_len)
	&& get_u_int8_t(packet->payload, 4) == packet->payload_packet_len - 5
	&& get_u_int8_t(packet->payload, 5) == 0xe0
	&& get_u_int16_t(packet->payload, 6) == 0 && get_u_int16_t(packet->payload, 8) == 0 && get_u_int8_t(packet->payload, 10) == 0) {
      NDPI_LOG_INFO(ndpi_struct, "found RDP\n");
    rdp_found:
      ndpi_int_rdp_add_connection(ndpi_struct, flow);
      ndpi_set_risk(ndpi_struct, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION); /* Remote assistance */
      return;
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  } else if(packet->udp != NULL) {
    u_int16_t s_port = ntohs(packet->udp->source);
    u_int16_t d_port = ntohs(packet->udp->dest);

    if((packet->payload_packet_len >= 10) && ((s_port == RDP_PORT) || (d_port == RDP_PORT))) {
      if(s_port == RDP_PORT) {
	/* Server -> Client */
	if(flow->l4.udp.rdp_from_srv_pkts == 0)
	  memcpy(flow->l4.udp.rdp_from_srv, packet->payload, 3), flow->l4.udp.rdp_from_srv_pkts = 1;
	else {
	  if(memcmp(flow->l4.udp.rdp_from_srv, packet->payload, 3) != 0)
	    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	  else {
	    flow->l4.udp.rdp_from_srv_pkts = 2 /* stage 2 */;
	    
	    if(flow->l4.udp.rdp_to_srv_pkts == 2)
	      goto rdp_found;
	  }
	}
      } else {
	/* Client -> Server */
	if(flow->l4.udp.rdp_to_srv_pkts == 0)
	  memcpy(flow->l4.udp.rdp_to_srv, packet->payload, 3), flow->l4.udp.rdp_to_srv_pkts = 1;
	else {
	  if(memcmp(flow->l4.udp.rdp_to_srv, packet->payload, 3) != 0)
	    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	  else {
	    flow->l4.udp.rdp_to_srv_pkts = 2 /* stage 2 */;
	    
	    if(flow->l4.udp.rdp_from_srv_pkts == 2)
	      goto rdp_found;
	  }
	}
      }
    } else
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}


void init_rdp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("RDP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_RDP,
				      ndpi_search_rdp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
