/*
 * dns.c
 *
 * Copyright (C) 2012-21 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DNS

#include "ndpi_api.h"

#define FLAGS_MASK 0x8000

// #define DNS_DEBUG 1

#define DNS_PORT   53
#define LLMNR_PORT 5355
#define MDNS_PORT  5353

#define PKT_LEN_ALERT 512

/* ndpi_main.c */
extern u_int8_t ndpi_iph_is_valid_and_not_fragmented(const struct ndpi_iphdr *iph, const u_int16_t ipsize);

static void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow);

/* *********************************************** */

static void ndpi_check_dns_type(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				u_int16_t dns_type) {
  /* https://en.wikipedia.org/wiki/List_of_DNS_record_types */

  switch(dns_type) {
    /* Obsolete record types */
  case 3:
  case 4:
  case 254:
  case 7:
  case 8:
  case 9:
  case 14:
  case 253:
  case 11:
  case 33:
  case 10:
  case 38:
  case 30:
  case 25:
  case 24:
  case 13:
  case 17:
  case 19:
  case 20:
  case 21:
  case 22:
  case 23:
  case 26:
  case 31:
  case 32:
  case 34:
  case 42:
  case 40:
  case 27:
  case 100:
  case 101:
  case 102:
  case 103:
  case 99:
  case 56:
  case 57:
  case 58:
  case 104:
  case 105:
  case 106:
  case 107:
  case 259:
    ndpi_set_risk(ndpi_struct, flow, NDPI_DNS_SUSPICIOUS_TRAFFIC);
    break;
  }
}

/* *********************************************** */

static u_int16_t checkPort(u_int16_t port) {
  switch(port) {
  case DNS_PORT:
    return(NDPI_PROTOCOL_DNS);
    break;
  case LLMNR_PORT:
    return(NDPI_PROTOCOL_LLMNR);
    break;
  case MDNS_PORT:
    return(NDPI_PROTOCOL_MDNS);
    break;
  }

  return(0);
}

/* *********************************************** */

static u_int16_t checkDNSSubprotocol(u_int16_t sport, u_int16_t dport) {
  u_int16_t rc = checkPort(sport);

  if(rc == 0)
    return(checkPort(dport));
  else
    return(rc);
}

/* *********************************************** */

static u_int16_t get16(int *i, const u_int8_t *payload) {
  u_int16_t v = *(u_int16_t*)&payload[*i];

  (*i) += 2;

  return(ntohs(v));
}

/* *********************************************** */

static u_int getNameLength(u_int i, const u_int8_t *payload, u_int payloadLen) {
  if(i >= payloadLen)
    return(0);
  else if(payload[i] == 0x00)
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
/*
  allowed chars for dns names A-Z 0-9 _ -
  Perl script for generation map:
  my @M;
  for(my $ch=0; $ch < 256; $ch++) {
  $M[$ch >> 5] |= 1 << ($ch & 0x1f) if chr($ch) =~ /[a-z0-9_-]/i;
  }
  print join(',', map { sprintf "0x%08x",$_ } @M),"\n";
*/

static uint32_t dns_validchar[8] =
  {
   0x00000000,0x03ff2000,0x87fffffe,0x07fffffe,0,0,0,0
  };

/* *********************************************** */

static int search_valid_dns(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow,
			    struct ndpi_dns_packet_header *dns_header,
			    int payload_offset, u_int8_t *is_query) {
  int x = payload_offset;

  memcpy(dns_header, (struct ndpi_dns_packet_header*)&flow->packet.payload[x],
	 sizeof(struct ndpi_dns_packet_header));

  dns_header->tr_id = ntohs(dns_header->tr_id);
  dns_header->flags = ntohs(dns_header->flags);
  dns_header->num_queries = ntohs(dns_header->num_queries);
  dns_header->num_answers = ntohs(dns_header->num_answers);
  dns_header->authority_rrs = ntohs(dns_header->authority_rrs);
  dns_header->additional_rrs = ntohs(dns_header->additional_rrs);

  x += sizeof(struct ndpi_dns_packet_header);

  /* 0x0000 QUERY */
  if((dns_header->flags & FLAGS_MASK) == 0x0000)
    *is_query = 1;
  /* 0x8000 RESPONSE */
  else if((dns_header->flags & FLAGS_MASK) == 0x8000)
    *is_query = 0;
  else {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET);
    return(1 /* invalid */);
  }

  if(*is_query) {
    /* DNS Request */
    if((dns_header->num_queries > 0) && (dns_header->num_queries <= NDPI_MAX_DNS_REQUESTS)
       //       && (dns_header->num_answers == 0)
       && (((dns_header->flags & 0x2800) == 0x2800 /* Dynamic DNS Update */)
	   || ((dns_header->flags & 0xFCF0) == 0x00) /* Standard Query */
	   || ((dns_header->num_answers == 0) && (dns_header->authority_rrs == 0)))) {
      /* This is a good query */
      while(x+2 < flow->packet.payload_packet_len) {
        if(flow->packet.payload[x] == '\0') {
          x++;
          flow->protos.dns.query_type = get16(&x, flow->packet.payload);
#ifdef DNS_DEBUG
          NDPI_LOG_DBG2(ndpi_struct, "query_type=%2d\n", flow->protos.dns.query_type);
	  printf("[DNS] [request] query_type=%d\n", flow->protos.dns.query_type);
#endif
	  break;
	} else
	  x++;
      }
    } else {
      ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET);
      return(1 /* invalid */);
    }
  } else {
    /* DNS Reply */
    flow->protos.dns.reply_code = dns_header->flags & 0x0F;

    if((dns_header->num_queries > 0) && (dns_header->num_queries <= NDPI_MAX_DNS_REQUESTS) /* Don't assume that num_queries must be zero */
       && ((((dns_header->num_answers > 0) && (dns_header->num_answers <= NDPI_MAX_DNS_REQUESTS))
	    || ((dns_header->authority_rrs > 0) && (dns_header->authority_rrs <= NDPI_MAX_DNS_REQUESTS))
	    || ((dns_header->additional_rrs > 0) && (dns_header->additional_rrs <= NDPI_MAX_DNS_REQUESTS))))
       ) {
      /* This is a good reply: we dissect it both for request and response */

      /* Leave the statement below commented necessary in case of call to ndpi_get_partial_detection() */
      x++;

      if(x < flow->packet.payload_packet_len && flow->packet.payload[x] != '\0') {
	while((x < flow->packet.payload_packet_len)
	      && (flow->packet.payload[x] != '\0')) {
	  x++;
	}

	x++;
      }

      x += 4;

      if(dns_header->num_answers > 0) {
	u_int16_t rsp_type;
	u_int16_t num;

	for(num = 0; num < dns_header->num_answers; num++) {
	  u_int16_t data_len;

	  if((x+6) >= flow->packet.payload_packet_len) {
	    break;
	  }

	  if((data_len = getNameLength(x, flow->packet.payload,
				       flow->packet.payload_packet_len)) == 0) {
	    break;
	  } else
	    x += data_len;

	  if((x+2) >= flow->packet.payload_packet_len) {
	    break;
	  }

	  rsp_type = get16(&x, flow->packet.payload);

#ifdef DNS_DEBUG
	  printf("[DNS] [response] response_type=%d\n", rsp_type);
#endif

	  ndpi_check_dns_type(ndpi_struct, flow, rsp_type);

	  flow->protos.dns.rsp_type = rsp_type;

	  /* here x points to the response "class" field */
	  if((x+12) <= flow->packet.payload_packet_len) {
	    x += 6;
	    data_len = get16(&x, flow->packet.payload);

	    if((x + data_len) <= flow->packet.payload_packet_len) {
	      // printf("[rsp_type: %u][data_len: %u]\n", rsp_type, data_len);

	      if(rsp_type == 0x05 /* CNAME */) {
		x += data_len;
		continue; /* Skip CNAME */
	      }

	      if((((rsp_type == 0x1) && (data_len == 4)) /* A */
		  || ((rsp_type == 0x1c) && (data_len == 16)) /* AAAA */
		  )) {
		memcpy(&flow->protos.dns.rsp_addr, flow->packet.payload + x, data_len);
	      }
	    }
	  }

	  break;
	}
      }

      if((flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_DNS)
	 || (flow->packet.detected_protocol_stack[1] == NDPI_PROTOCOL_DNS)) {
	/* Request already set the protocol */
	// flow->extra_packets_func = NULL; /* Removed so the caller can keep dissecting DNS flows */
      } else {
	/* We missed the request */
	u_int16_t s_port = flow->packet.udp ? ntohs(flow->packet.udp->source) : ntohs(flow->packet.tcp->source);

	ndpi_set_detected_protocol(ndpi_struct, flow, checkPort(s_port), NDPI_PROTOCOL_UNKNOWN);
      }
    }
  }

  /* Valid */
  return(0);
}

/* *********************************************** */

static int search_dns_again(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  /* possibly dissect the DNS reply */
  ndpi_search_dns(ndpi_struct, flow);

  /* Possibly more processing */
  return(1);
}

/* *********************************************** */

static void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  int payload_offset;
  u_int8_t is_query;
  u_int16_t s_port = 0, d_port = 0;

  NDPI_LOG_DBG(ndpi_struct, "search DNS\n");

  if(flow->packet.udp != NULL) {
    s_port = ntohs(flow->packet.udp->source);
    d_port = ntohs(flow->packet.udp->dest);
    payload_offset = 0;
  } else if(flow->packet.tcp != NULL) /* pkt size > 512 bytes */ {
    s_port = ntohs(flow->packet.tcp->source);
    d_port = ntohs(flow->packet.tcp->dest);
    payload_offset = 2;
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if(((s_port == DNS_PORT) || (d_port == DNS_PORT)
      || (s_port == MDNS_PORT) || (d_port == MDNS_PORT)
      || (d_port == LLMNR_PORT))
     && (flow->packet.payload_packet_len > sizeof(struct ndpi_dns_packet_header)+payload_offset)) {
    struct ndpi_dns_packet_header dns_header;
    int j = 0, max_len, off;
    int invalid = search_valid_dns(ndpi_struct, flow, &dns_header, payload_offset, &is_query);
    ndpi_protocol ret;
    u_int num_queries, idx;

    ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;
    ret.app_protocol    = (d_port == LLMNR_PORT) ? NDPI_PROTOCOL_LLMNR : ((d_port == MDNS_PORT) ? NDPI_PROTOCOL_MDNS : NDPI_PROTOCOL_DNS);

    if(invalid) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    /* extract host name server */
    max_len = sizeof(flow->host_server_name)-1;
    off = sizeof(struct ndpi_dns_packet_header) + payload_offset;

    /* Before continuing let's dissect the following queries to see if they are valid */
    for(idx=off, num_queries=0; (num_queries < dns_header.num_queries) && (idx < flow->packet.payload_packet_len);) {
      u_int16_t i, tot_len = 0;

      for(i=idx; i<flow->packet.payload_packet_len;) {
	u_int8_t is_ptr = 0, name_len = flow->packet.payload[i]; /* Lenght of the individual name blocks aaa.bbb.com */

	if(name_len == 0) {
	  tot_len++; /* \0 */
	  /* End of query */
	  break;
	} else if((name_len & 0xC0) == 0xC0)
	  is_ptr = 1, name_len = 0; /* Pointer */

#ifdef DNS_DEBUG
	if((!is_ptr) && (name_len > 0)) {
	  printf("[DNS] [name_len: %u][", name_len);

	  {
	    int idx;

	    for(idx=0; idx<name_len; idx++)
	      printf("%c", flow->packet.payload[i+1+idx]);

	    printf("]\n");
	  }
	}
#endif

	i += name_len+1, tot_len += name_len+1;
	if(is_ptr) break;
      } /* for */

#ifdef DNS_DEBUG
      printf("[DNS] [tot_len: %u]\n\n", tot_len+4 /* type + class */);
#endif

      if(((i+4 /* Skip query type and class */) > flow->packet.payload_packet_len)
	 || ((flow->packet.payload[i+1] == 0x0) && (flow->packet.payload[i+2] == 0x0)) /* Query type cannot be 0 */
	 || (tot_len > 253)
	 ) {
	/* Invalid */
#ifdef DNS_DEBUG
	printf("[DNS] Invalid query len [%u >= %u]\n", i+4, flow->packet.payload_packet_len);
#endif
	ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET);
	break;
      } else {
	idx = i+5, num_queries++;
      }
    } /* for */

    while((j < max_len) && (off < flow->packet.payload_packet_len) && (flow->packet.payload[off] != '\0')) {
      uint8_t c, cl = flow->packet.payload[off++];

      if(((cl & 0xc0) != 0) || // we not support compressed names in query
	 (off + cl  >= flow->packet.payload_packet_len)) {
	j = 0;
	break;
      }

      if(j && (j < max_len)) flow->host_server_name[j++] = '.';

      while((j < max_len) && (cl != 0)) {
	u_int32_t shift;

	c = flow->packet.payload[off++];
	shift = ((u_int32_t) 1) << (c & 0x1f);
	flow->host_server_name[j++] = tolower((dns_validchar[c >> 5] & shift) ? c : '_');
	cl--;
      }
    }

    flow->host_server_name[j] = '\0';

    if(j > 0) {
      ndpi_protocol_match_result ret_match;

      ndpi_check_dga_name(ndpi_struct, flow, (char*)flow->host_server_name, 1);

      ret.app_protocol = ndpi_match_host_subprotocol(ndpi_struct, flow,
						     (char *)flow->host_server_name,
						     strlen((const char*)flow->host_server_name),
						     &ret_match,
						     NDPI_PROTOCOL_DNS);

      if(ret_match.protocol_category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
	flow->category = ret_match.protocol_category;

      if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN)
	ret.master_protocol = checkDNSSubprotocol(s_port, d_port);
      else
	ret.master_protocol = NDPI_PROTOCOL_DNS;
    }

    /* Report if this is a DNS query or reply */
    flow->protos.dns.is_query = is_query;

    if(is_query) {
      /* In this case we say that the protocol has been detected just to let apps carry on with their activities */
      ndpi_set_detected_protocol(ndpi_struct, flow, ret.app_protocol, ret.master_protocol);

      /* This is necessary to inform the core to call this dissector again */
      flow->check_extra_packets = 1;

      /* Don't use just 1 as in TCP DNS more packets could be returned (e.g. ACK). */
      flow->max_extra_packets_to_check = 5;
      flow->extra_packets_func = search_dns_again;
      return; /* The response will set the verdict */
    }

    flow->protos.dns.num_queries = (u_int8_t)dns_header.num_queries,
      flow->protos.dns.num_answers = (u_int8_t) (dns_header.num_answers + dns_header.authority_rrs + dns_header.additional_rrs);

#ifdef DNS_DEBUG
    NDPI_LOG_DBG2(ndpi_struct, "[num_queries=%d][num_answers=%d][reply_code=%u][rsp_type=%u][host_server_name=%s]\n",
		  flow->protos.dns.num_queries, flow->protos.dns.num_answers,
		  flow->protos.dns.reply_code, flow->protos.dns.rsp_type, flow->host_server_name
		  );
#endif

    if(flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
      /**
	 Do not set the protocol with DNS if ndpi_match_host_subprotocol() has
	 matched a subprotocol
      **/
      NDPI_LOG_INFO(ndpi_struct, "found DNS\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, ret.app_protocol, ret.master_protocol);
    } else {
      if((flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_DNS)
	 || (flow->packet.detected_protocol_stack[1] == NDPI_PROTOCOL_DNS))
	;
      else
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
  }

  if(flow->packet_counter > 3)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

  if((flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_DNS)
     || (flow->packet.detected_protocol_stack[1] == NDPI_PROTOCOL_DNS)) {
    /* TODO: add support to RFC6891 to avoid some false positives */
    if(flow->packet.udp != NULL && flow->packet.payload_packet_len > PKT_LEN_ALERT)
      ndpi_set_risk(ndpi_struct, flow, NDPI_DNS_LARGE_PACKET);

    if(flow->packet.iph != NULL) {
      /* IPv4 */
      u_int8_t flags = ((u_int8_t*)flow->packet.iph)[6];

      /* 0: fragmented; 1: not fragmented */
      if((flags & 0x20)
	 || (ndpi_iph_is_valid_and_not_fragmented(flow->packet.iph, flow->packet.l3_packet_len) == 0)) {
	ndpi_set_risk(ndpi_struct, flow, NDPI_DNS_FRAGMENTED);
      }
    } else if(flow->packet.iphv6 != NULL) {
      /* IPv6 */
      const struct ndpi_ip6_hdrctl *ip6_hdr = &flow->packet.iphv6->ip6_hdr;

      if(ip6_hdr->ip6_un1_nxt == 0x2C /* Next Header: Fragment Header for IPv6 (44) */) {
	ndpi_set_risk(ndpi_struct, flow, NDPI_DNS_FRAGMENTED);
      }	
    }
  }
}

/* *********************************************** */

void init_dns_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("DNS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DNS,
				      ndpi_search_dns,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;

}
