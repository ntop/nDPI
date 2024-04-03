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
#include "ndpi_private.h"

static void ndpi_int_rdp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow) {
  NDPI_LOG_INFO(ndpi_struct, "found RDP\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RDP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found RDP"); /* Remote assistance */
}

static void ndpi_search_rdp(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow) {
  const struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
	
  NDPI_LOG_DBG(ndpi_struct, "search RDP\n");

  if (packet->tcp != NULL) {
    if(packet->payload_packet_len > 13 &&
       tpkt_verify_hdr(packet) &&
       /* COTP */
       packet->payload[4] == packet->payload_packet_len - 5) {

      if(current_pkt_from_client_to_server(ndpi_struct, flow)) {
        if(packet->payload[5] == 0xE0 && /* COTP CR */
	   ((packet->payload[11] == 0x01 && /* RDP Negotiation Request */
             packet->payload[13] == 0x08 /* RDP Length */) ||
	    (packet->payload_packet_len > 17 &&
	     memcmp(&packet->payload[11], "Cookie:", 7) == 0))) /* RDP Cookie */ {
          ndpi_int_rdp_add_connection(ndpi_struct, flow);
          return;
	}
      } else {
        /* Asymmetric detection via RDP Negotiation Response */
        if(packet->payload[5] == 0xD0 && /* COTP CC */
	   packet->payload[11] == 0x02 && /* RDP Negotiation Response */
           packet->payload[13] == 0x08 /* RDP Length */) {
          ndpi_int_rdp_add_connection(ndpi_struct, flow);
          return;
	}
      }
    }
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  } else if(packet->udp != NULL) {
    u_int16_t s_port = ntohs(packet->udp->source);
    u_int16_t d_port = ntohs(packet->udp->dest);

    /* Detection:
       * initial syn/syn-ack pair for RDPUDP v1 & v2
       * mid-flow (only v1) */

    if((packet->payload_packet_len >= 10) && ((s_port == RDP_PORT) || (d_port == RDP_PORT))) {
      if(s_port == RDP_PORT) {
	/* Server -> Client */
	if(flow->l4.udp.rdp_from_srv_pkts == 0) {
	  if(memcmp(packet->payload, flow->l4.udp.rdp_from_srv, 3) == 0 &&
	     packet->payload_packet_len >= 16 &&
	     (ntohs(get_u_int16_t(packet->payload, 6)) & 0x0003) && /* Flags: syn-ack */
	     ntohs(get_u_int16_t(packet->payload, 12)) <= 1600 && /* Sensible values for upstream MTU */
	     ntohs(get_u_int16_t(packet->payload, 14)) <= 1600) { /* Sensible values for downstream MTU */
	    /* Initial "syn-ack" */
	    ndpi_int_rdp_add_connection(ndpi_struct, flow);
	    return;
	  } else {
	    /* Mid-flow session? */
	    memcpy(flow->l4.udp.rdp_from_srv, packet->payload, 3), flow->l4.udp.rdp_from_srv_pkts = 1;
	  }
	} else {
	  if(memcmp(flow->l4.udp.rdp_from_srv, packet->payload, 3) != 0)
	    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	  else {
	    flow->l4.udp.rdp_from_srv_pkts = 2 /* stage 2 */;

	    if(flow->l4.udp.rdp_to_srv_pkts == 2) {
	      ndpi_int_rdp_add_connection(ndpi_struct, flow);
	      return;
	    }
	  }
	}
      } else {
	/* Client -> Server */
	if(flow->l4.udp.rdp_to_srv_pkts == 0) {
	  if(get_u_int32_t(packet->payload, 0) == 0xFFFFFFFF &&
	     packet->payload_packet_len >= 16 &&
	     (ntohs(get_u_int16_t(packet->payload, 6)) & 0x0001) && /* Flags: syn */
	     ntohs(get_u_int16_t(packet->payload, 12)) <= 1600 && /* Sensible values for upstream MTU */
	     ntohs(get_u_int16_t(packet->payload, 14)) <= 1600) { /* Sensible values for downstream MTU */
	    /* Initial "syn" */
	    memcpy(flow->l4.udp.rdp_from_srv, packet->payload + 8, 3);
	  } else {
	    /* Mid-flow session? */
	    memcpy(flow->l4.udp.rdp_to_srv, packet->payload, 3), flow->l4.udp.rdp_to_srv_pkts = 1;
	  }
	} else {
	  if(memcmp(flow->l4.udp.rdp_to_srv, packet->payload, 3) != 0)
	    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	  else {
	    flow->l4.udp.rdp_to_srv_pkts = 2 /* stage 2 */;
	    
	    if(flow->l4.udp.rdp_from_srv_pkts == 2) {
              ndpi_int_rdp_add_connection(ndpi_struct, flow);
              return;
	    }
	  }
	}
      }
    } else
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}


void init_rdp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("RDP", ndpi_struct, *id,
				      NDPI_PROTOCOL_RDP,
				      ndpi_search_rdp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
