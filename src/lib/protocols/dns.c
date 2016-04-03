/*
 * dns.c
 *
 * Copyright (C) 2012-16 - ntop.org
 *
 * Michele Campus - <campus@ntop.org>
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

#ifdef NDPI_PROTOCOL_DNS

#define FLAGS_MASK 0x8000

void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

  int x;
  u_int8_t is_query, ret_code;
  u_int16_t s_port = 0;
  u_int16_t d_port = 0;
  
  NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "search DNS.\n");

  if(flow->packet.udp != NULL)
  {
    s_port = ntohs(flow->packet.udp->source);
    d_port = ntohs(flow->packet.udp->dest);
    x = 0;
  }
  else if(flow->packet.tcp != NULL) /* pkt size > 512 bytes */
  {
    s_port = ntohs(flow->packet.tcp->source);
    d_port = ntohs(flow->packet.tcp->dest);
    x = 2;
  }
  else
  {
    NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "exclude DNS.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DNS);
  }

  if((s_port == 53 || d_port == 53 || d_port == 5355)
     && (flow->packet.payload_packet_len > sizeof(struct ndpi_dns_packet_header)))
  {
    struct ndpi_dns_packet_header dns_header;
    int invalid = 0;

    memcpy(&dns_header, (struct ndpi_dns_packet_header*) &flow->packet.payload[x], sizeof(struct ndpi_dns_packet_header));
    dns_header.tr_id = ntohs(dns_header.tr_id);
    dns_header.flags = ntohs(dns_header.flags);
    dns_header.num_queries = ntohs(dns_header.num_queries);
    dns_header.num_answers = ntohs(dns_header.num_answers);
    dns_header.authority_rrs = ntohs(dns_header.authority_rrs);
    dns_header.additional_rrs = ntohs(dns_header.additional_rrs);

    /* 0x0000 QUERY */
    if((dns_header.flags & FLAGS_MASK) == 0x0000)
      is_query = 1;
    /* 0x8000 RESPONSE */
    else if((dns_header.flags & FLAGS_MASK) != 0x8000)
      is_query = 0;
    else
      invalid = 1;

    if(!invalid) {
      if(is_query) {
	/* DNS Request */
	if((dns_header.num_queries > 0) && (dns_header.num_queries <= NDPI_MAX_DNS_REQUESTS)
	   && (((dns_header.flags & 0x2800) == 0x2800 /* Dynamic DNS Update */)
	       || ((dns_header.num_answers == 0) && (dns_header.authority_rrs == 0)))) {
	  /* This is a good query */
	} else
	  invalid = 1;
      } else {
	/* DNS Reply */
	if((dns_header.num_queries > 0) && (dns_header.num_queries <= NDPI_MAX_DNS_REQUESTS) /* Don't assume that num_queries must be zero */
	   && (((dns_header.num_answers > 0) && (dns_header.num_answers <= NDPI_MAX_DNS_REQUESTS))
	       || ((dns_header.authority_rrs > 0) && (dns_header.authority_rrs <= NDPI_MAX_DNS_REQUESTS))
	       || ((dns_header.additional_rrs > 0) && (dns_header.additional_rrs <= NDPI_MAX_DNS_REQUESTS)))
	   ) {
	  /* This is a good reply */
	} else
	  invalid = 1;
      }
    }

    if(invalid) {
      NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "exclude DNS.\n");
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DNS);    
      return;
    }

    /* extract host name server */
    ret_code = (is_query == 0) ? 0 : (dns_header.flags & 0x0F);
    int j = 0;
    int off = sizeof(struct ndpi_dns_packet_header) + 1;
    while((flow->packet.payload[off] != '\0'))
    {
      if(off < flow->packet.payload_packet_len)
      {
	flow->host_server_name[j] = flow->packet.payload[off];
	if(j < strlen(flow->host_server_name))
	{
	  if(flow->host_server_name[j] < ' ')
	    flow->host_server_name[j] = '.';
	  j++;
	}
	off++;
      }
    }
    flow->host_server_name[j] = '\0';

    flow->protos.dns.num_answers = (u_int8_t) (dns_header.num_answers + dns_header.authority_rrs + dns_header.additional_rrs);
    flow->protos.dns.ret_code = ret_code;

    if(j > 0)
      ndpi_match_host_subprotocol(ndpi_struct, flow, 
				  (char *)flow->host_server_name,
				  strlen((const char*)flow->host_server_name),
				  NDPI_PROTOCOL_DNS);
    
    if(flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
    {
      /**
	 Do not set the protocol with DNS if ndpi_match_host_subprotocol() has
	 matched a subprotocol
      **/
      NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "found DNS.\n");      
      ndpi_set_detected_protocol(ndpi_struct, flow, (d_port == 5355) ? NDPI_PROTOCOL_LLMNR : NDPI_PROTOCOL_DNS, NDPI_PROTOCOL_UNKNOWN);
    } else {
      NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "exclude DNS.\n");
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DNS);
    }
  }
}

void init_dns_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("DNS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DNS,
				      ndpi_search_dns,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
