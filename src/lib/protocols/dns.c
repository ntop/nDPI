/*
 * dns.c
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


#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_DNS

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

static char* ndpi_intoa_v4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  uint byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* *********************************************** */

static u_int16_t get16(int *i, const u_int8_t *payload) {
  u_int16_t v = *(u_int16_t*)&payload[*i];

  (*i) += 2;

  return(ntohs(v));
}

/* *********************************************** */

struct dns_packet_header {
  u_int16_t transaction_id, flags, num_queries, answer_rrs, authority_rrs, additional_rrs;
} __attribute__((packed));

void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;
  
#define NDPI_MAX_DNS_REQUESTS			16

  NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "search DNS.\n");
  
  if (packet->udp != NULL) {
    sport = ntohs(packet->udp->source),  dport = ntohs(packet->udp->dest);
    NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "calculated dport over UDP.\n");
  } else  if(packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "calculated dport over tcp.\n");
  }

  if(((dport == 53) || (sport == 53) || (dport == 5355))
     && (packet->payload_packet_len > sizeof(struct dns_packet_header))) {
    int i = packet->tcp ? 2 : 0;
    struct dns_packet_header header, *dns = (struct dns_packet_header*)&packet->payload[i];
    u_int8_t is_query, ret_code, is_dns = 0;
    u_int32_t a_record[NDPI_MAX_DNS_REQUESTS] = { 0 }, query_offset, num_a_records = 0;

    header.flags = ntohs(dns->flags);
    header.transaction_id = ntohs(dns->transaction_id);
    header.num_queries = ntohs(dns->num_queries);
    header.answer_rrs = ntohs(dns->answer_rrs);
    header.authority_rrs = ntohs(dns->authority_rrs);
    header.additional_rrs = ntohs(dns->additional_rrs);
    is_query = (header.flags & 0x8000) ? 0 : 1;
    ret_code = is_query ? 0 : (header.flags & 0x0F);
    i += sizeof(struct dns_packet_header);
    query_offset = i;

    if(is_query) {
      /* DNS Request */
      if((header.num_queries > 0) && (header.num_queries <= NDPI_MAX_DNS_REQUESTS)
	 && (((header.flags & 0x2800) == 0x2800 /* Dynamic DNS Update */)
	     || ((header.answer_rrs == 0) && (header.authority_rrs == 0)))) {
	/* This is a good query */
	is_dns = 1;

	if(header.num_queries > 0) {
	  while(i < packet->payload_packet_len) {
	      if(packet->payload[i] == '\0') {
		i++;
		flow->protos.dns.query_type = get16(&i, packet->payload);
		break;
	      } else
		i++;
	    }
	}
      }
    } else {
      /* DNS Reply */

      flow->server_id = flow->dst;

      if((header.num_queries <= NDPI_MAX_DNS_REQUESTS) /* Don't assume that num_queries must be zero */
	 && (((header.answer_rrs > 0) && (header.answer_rrs <= NDPI_MAX_DNS_REQUESTS))
	     || ((header.authority_rrs > 0) && (header.authority_rrs <= NDPI_MAX_DNS_REQUESTS))
	     || ((header.additional_rrs > 0) && (header.additional_rrs <= NDPI_MAX_DNS_REQUESTS)))
	 ) {
	/* This is a good reply */
	is_dns = 1;

	i++;
	
	if(packet->payload[i] != '\0') {
	  while((i < packet->payload_packet_len)
		&& (packet->payload[i] != '\0')) {
	    i++;
	  }
	  
	  i++;
	}

	i += 4;

	if(header.answer_rrs > 0) {
	  u_int16_t rsp_type /*, rsp_class */;
	  u_int16_t num;

	  for(num = 0; num < header.answer_rrs; num++) {
	    u_int16_t data_len;
	
	    if((i+6) >= packet->payload_packet_len) {
	      break;
	    }

	    if((data_len = getNameLength(i, packet->payload, packet->payload_packet_len)) == 0) {
	      break;
	    } else
	      i += data_len;
	
	    rsp_type = get16(&i, packet->payload);
	    // rsp_class = get16(&i, packet->payload);

	    i += 4;
	    data_len = get16(&i, packet->payload);

	    if((data_len <= 1) || (data_len > (packet->payload_packet_len-i))) {
	      break;
	    }

	    flow->protos.dns.rsp_type = rsp_type;

	    if(rsp_type == 1 /* A */) {
	      if(data_len == 4) {
		u_int32_t v = ntohl(*((u_int32_t*)&packet->payload[i]));

		if(num_a_records < (NDPI_MAX_DNS_REQUESTS-1))
		  a_record[num_a_records++] = v;
		else
		  break; /* One record is enough */
	      }
	    }
	
	    if(data_len == 0) {
	      break;
	    }

	    i += data_len;
	  } /* for */
	}
      }

      if((header.num_queries <= NDPI_MAX_DNS_REQUESTS)
	 && ((header.answer_rrs == 0)
	     || (header.authority_rrs == 0)
	     || (header.additional_rrs == 0))
	 && (ret_code != 0 /* 0 == OK */)
	 ) {
	/* This is a good reply */
	is_dns = 1;
      }
    }

    if(is_dns) {
      int j = 0;

      flow->protos.dns.num_queries = (u_int8_t)header.num_queries, 
	flow->protos.dns.num_answers = (u_int8_t)(header.answer_rrs+header.authority_rrs+header.additional_rrs),
      flow->protos.dns.ret_code = ret_code;

      i = query_offset+1;

      while((i < packet->payload_packet_len)
	    && (j < (sizeof(flow->host_server_name)-1))	  
	    && (packet->payload[i] != '\0')) {
	flow->host_server_name[j] = tolower(packet->payload[i]);
	if(flow->host_server_name[j] < ' ')
	  flow->host_server_name[j] = '.';	
	j++, i++;
      }

      if(a_record[0] != 0) {
	char a_buf[32];
	int i;

	for(i=0; i<num_a_records; i++) {
	  j += snprintf((char*)&flow->host_server_name[j], sizeof(flow->host_server_name)-1-j, "%s%s",
			(i == 0) ? "@" : ";",
			ndpi_intoa_v4(a_record[i], a_buf, sizeof(a_buf)));
	}
      }
		      
      flow->host_server_name[j] = '\0';

      if(j > 0) {
#ifdef DEBUG
	printf("==> %s\n", flow->host_server_name);
#endif

	if(ndpi_struct->match_dns_host_names)
	  ndpi_match_string_subprotocol(ndpi_struct, flow, 
					(char *)flow->host_server_name,
					strlen((const char*)flow->host_server_name));
      }

      i++;

      memcpy(&flow->protos.dns.query_type, &packet->payload[i], 2); 
      flow->protos.dns.query_type  = ntohs(flow->protos.dns.query_type), i += 2;

      memcpy(&flow->protos.dns.query_class, &packet->payload[i], 2); 
      flow->protos.dns.query_class  = ntohs(flow->protos.dns.query_class), i += 2;

#ifdef DEBUG
      printf("%s [type=%04X][class=%04X]\n", flow->host_server_name, flow->protos.dns.query_type, flow->protos.dns.query_class);
#endif

      if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
	/* 
	   Do not set the protocol with DNS if ndpi_match_string_subprotocol() has
	   matched a subprotocol
	*/
	NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "found DNS.\n");      
	ndpi_int_add_connection(ndpi_struct, flow, (dport == 5355) ? NDPI_PROTOCOL_LLMNR : NDPI_PROTOCOL_DNS, NDPI_REAL_PROTOCOL);
      }
    } else {
      flow->protos.dns.bad_packet = 1;
      NDPI_LOG(NDPI_PROTOCOL_DNS, ndpi_struct, NDPI_LOG_DEBUG, "exclude DNS.\n");
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DNS);
    }
  }
}
#endif
