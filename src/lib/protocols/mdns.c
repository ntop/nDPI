/*
 * mdns.c
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

#ifdef NDPI_PROTOCOL_MDNS

#define NDPI_MAX_MDNS_REQUESTS  128


/**
   MDNS header is similar to dns header

   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  ID = 0x0000                  |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     FLAGS                     |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    QDCOUNT                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    ANCOUNT                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    NSCOUNT                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    ARCOUNT                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/


static void ndpi_int_mdns_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MDNS, NDPI_PROTOCOL_UNKNOWN);
}

static int ndpi_int_check_mdns_payload(struct ndpi_detection_module_struct
				       *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if((packet->payload[2] & 0x80) == 0 &&
     ntohs(get_u_int16_t(packet->payload, 4)) <= NDPI_MAX_MDNS_REQUESTS &&
     ntohs(get_u_int16_t(packet->payload, 6)) <= NDPI_MAX_MDNS_REQUESTS) {
    
    NDPI_LOG(NDPI_PROTOCOL_MDNS, ndpi_struct, NDPI_LOG_DEBUG, "found MDNS with question query.\n");
    return 1;    
  }
  else if((packet->payload[2] & 0x80) != 0 &&
	  ntohs(get_u_int16_t(packet->payload, 4)) == 0 &&
	  ntohs(get_u_int16_t(packet->payload, 6)) <= NDPI_MAX_MDNS_REQUESTS &&
	  ntohs(get_u_int16_t(packet->payload, 6)) != 0) {
    char answer[256];
    int i, j, len;

    for(i=13, j=0; (packet->payload[i] != 0) && (i < packet->payload_packet_len) && (i < (sizeof(answer)-1)); i++)
      answer[j++] = (packet->payload[i] < 13) ? '.' : packet->payload[i];
	
    answer[j] = '\0';

    /* printf("==> [%d] %s\n", j, answer); */

    len = ndpi_min(sizeof(flow->protos.mdns.answer)-1, j);
    strncpy(flow->protos.mdns.answer, (const char *)answer, len);
    flow->protos.mdns.answer[len] = '\0';

    NDPI_LOG(NDPI_PROTOCOL_MDNS, ndpi_struct, NDPI_LOG_DEBUG, "found MDNS with answer query.\n");
    return 1;
  }
  
  return 0;
}

void ndpi_search_mdns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport;
  
  /**
     information from http://www.it-administrator.de/lexikon/multicast-dns.html 
  */
  
  /* check if UDP packet */
  if(packet->udp != NULL) {   
    /* read destination port */
    dport = ntohs(packet->udp->dest);

    /* check standard MDNS ON port 5353 */
    if(dport == 5353 && packet->payload_packet_len >= 12) {
      /* mdns protocol must have destination address 224.0.0.251 */
      if(packet->iph != NULL && ntohl(packet->iph->daddr) == 0xe00000fb) {

	NDPI_LOG(NDPI_PROTOCOL_MDNS, ndpi_struct,
		 NDPI_LOG_DEBUG, "found MDNS with destination address 224.0.0.251 (=0xe00000fb)\n");
	
	if(ndpi_int_check_mdns_payload(ndpi_struct, flow) == 1) {
	  ndpi_int_mdns_add_connection(ndpi_struct, flow);
	  return;
	}
      }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
      if(packet->iphv6 != NULL) {
	const u_int32_t *daddr = packet->iphv6->ip6_dst.u6_addr.u6_addr32;
	if(daddr[0] == htonl(0xff020000) && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == htonl(0xfb)) {

	  NDPI_LOG(NDPI_PROTOCOL_MDNS, ndpi_struct,
		   NDPI_LOG_DEBUG, "found MDNS with destination address ff02::fb\n");
	  
	  if(ndpi_int_check_mdns_payload(ndpi_struct, flow) == 1) {
	    ndpi_int_mdns_add_connection(ndpi_struct, flow);
	    return;
	  }
	}
      }
#endif
    }
  }
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MDNS);
}


void init_mdns_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("MDNS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MDNS,
				      ndpi_search_mdns,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
