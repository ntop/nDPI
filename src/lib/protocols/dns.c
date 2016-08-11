/*
 * dns.c
 *
 * Copyright (C) 2012-16 - ntop.org
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

/* #define DNS_DEBUG 1 */

/* *********************************************** */

static u_int16_t get16(int *i, const u_int8_t *payload) {
  u_int16_t v = *(u_int16_t*)&payload[*i];
  
  (*i) += 2;
  
  return(ntohs(v));
}

/* *********************************************** */

static u_int getNameLength(u_int i, const u_int8_t *payload, u_int payloadLen) {
  if(payload[i] == 0x00)
    return(1);
  else if(payload[i] == 0xC0)
    return(2);
  else {
    u_int8_t len = payload[i];
    u_int8_t off = len + 1;
	
    if(off == 0) /* Bad packet */
      return(0);
    else
      return(off + getNameLength(i+off, payload, payloadLen));
  }
}

/* *********************************************** */

void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  int x;
  u_int8_t is_query;
  u_int16_t s_port = 0, d_port = 0;
  
  NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "search DNS.\n");

  if(flow->packet.udp != NULL) {
    s_port = ntohs(flow->packet.udp->source);
    d_port = ntohs(flow->packet.udp->dest);
    x = 0;
  } else if(flow->packet.tcp != NULL) /* pkt size > 512 bytes */ {
    s_port = ntohs(flow->packet.tcp->source);
    d_port = ntohs(flow->packet.tcp->dest);
    x = 2;
  } else {
    NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "exclude DNS.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DNS);
  }

  if((s_port == 53 || d_port == 53 || d_port == 5355)
     && (flow->packet.payload_packet_len > sizeof(struct ndpi_dns_packet_header)+x)) {
    struct ndpi_dns_packet_header dns_header;
    int invalid = 0;

    memcpy(&dns_header, (struct ndpi_dns_packet_header*) &flow->packet.payload[x], sizeof(struct ndpi_dns_packet_header));
    dns_header.tr_id = ntohs(dns_header.tr_id);
    dns_header.flags = ntohs(dns_header.flags);
    dns_header.num_queries = ntohs(dns_header.num_queries);
    dns_header.num_answers = ntohs(dns_header.num_answers);
    dns_header.authority_rrs = ntohs(dns_header.authority_rrs);
    dns_header.additional_rrs = ntohs(dns_header.additional_rrs);
    x += sizeof(struct ndpi_dns_packet_header);

    /* 0x0000 QUERY */
    if((dns_header.flags & FLAGS_MASK) == 0x0000)
      is_query = 1;
    /* 0x8000 RESPONSE */
    else if((dns_header.flags & FLAGS_MASK) == 0x8000)
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

	  if(dns_header.num_queries > 0) {
	    while(x < flow->packet.payload_packet_len) {
	      if(flow->packet.payload[x] == '\0') {
		x++;
		flow->protos.dns.query_type = get16(&x, flow->packet.payload);
#ifdef DNS_DEBUG		
		printf("[%s:%d] query_type=%2d\n", __FILE__, __LINE__, flow->protos.dns.query_type);
#endif
		break;
	      } else
		x++;
	    }
	  }
	} else
	  invalid = 1;
	
      } else {
	/* DNS Reply */

	flow->protos.dns.reply_code = dns_header.flags & 0x0F;

	if((dns_header.num_queries > 0) && (dns_header.num_queries <= NDPI_MAX_DNS_REQUESTS) /* Don't assume that num_queries must be zero */
	   && (((dns_header.num_answers > 0) && (dns_header.num_answers <= NDPI_MAX_DNS_REQUESTS))
	       || ((dns_header.authority_rrs > 0) && (dns_header.authority_rrs <= NDPI_MAX_DNS_REQUESTS))
	       || ((dns_header.additional_rrs > 0) && (dns_header.additional_rrs <= NDPI_MAX_DNS_REQUESTS)))
	   ) {
	  /* This is a good reply */
	  if(ndpi_struct->dns_dissect_response) {
	    x++;
	  
	    if(flow->packet.payload[x] != '\0') {
	      while((x < flow->packet.payload_packet_len)
		    && (flow->packet.payload[x] != '\0')) {
		x++;
	      }
	        
	      x++;
	    }

	    x += 4;

	    if(dns_header.num_answers > 0) {
	      u_int16_t rsp_type;
	      u_int16_t num;

	      for(num = 0; num < dns_header.num_answers; num++) {
		u_int16_t data_len;
  
		if((x+6) >= flow->packet.payload_packet_len) {
		  break;
		}

		if((data_len = getNameLength(x, flow->packet.payload, flow->packet.payload_packet_len)) == 0) {
		  break;
		} else
		  x += data_len;
 
		rsp_type = get16(&x, flow->packet.payload);
		flow->protos.dns.rsp_type = rsp_type;
		break;
	      }
	    }
	  }
	}
      }

      if(invalid) {
	NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "exclude DNS.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DNS);    
	return;
      }

      /* extract host name server */
      int j = 0, max_len = sizeof(flow->host_server_name)-1, off = sizeof(struct ndpi_dns_packet_header) + 1;

      while(off < flow->packet.payload_packet_len && flow->packet.payload[off] != '\0') {
	flow->host_server_name[j] = flow->packet.payload[off];
	if(j < max_len) {
	  if(flow->host_server_name[j] < ' ')
	    flow->host_server_name[j] = '.';
	  j++;
	} else
	  break;

	off++;
      }

      flow->host_server_name[j] = '\0';

      flow->protos.dns.num_queries = (u_int8_t)dns_header.num_queries,
	flow->protos.dns.num_answers = (u_int8_t) (dns_header.num_answers + dns_header.authority_rrs + dns_header.additional_rrs);

      if(j > 0)
	ndpi_match_host_subprotocol(ndpi_struct, flow, 
				    (char *)flow->host_server_name,
				    strlen((const char*)flow->host_server_name),
				    NDPI_PROTOCOL_DNS);

#ifdef DNS_DEBUG		
      printf("[%s:%d] [num_queries=%d][num_answers=%d][reply_code=%u][rsp_type=%u][host_server_name=%s]\n",
	     __FILE__, __LINE__,
	     flow->protos.dns.num_queries, flow->protos.dns.num_answers,
	     flow->protos.dns.reply_code, flow->protos.dns.rsp_type, flow->host_server_name
	     );
#endif
    
      if(flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
	if(is_query && ndpi_struct->dns_dissect_response)
	  return; /* The response will set the verdict */
	
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
