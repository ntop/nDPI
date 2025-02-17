/*
 * dns.c
 *
 * Copyright (C) 2012-22 - ntop.org
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
#include "ndpi_private.h"

#define FLAGS_MASK 0x8000

/* #define DNS_DEBUG 1 */

#define DNS_PORT   53
#define LLMNR_PORT 5355
#define MDNS_PORT  5353

#define PKT_LEN_ALERT 512


static void search_dns(struct ndpi_detection_module_struct *ndpi_struct,
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
    /* case 33: */ /* SRV */
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
    ndpi_set_risk(ndpi_struct, flow, NDPI_DNS_SUSPICIOUS_TRAFFIC, "Obsolete DNS record type");
    break;
  }
}

/* *********************************************** */

static u_int16_t checkPort(u_int16_t port) {
  switch(port) {
  case DNS_PORT:
    return(NDPI_PROTOCOL_DNS);
  case LLMNR_PORT:
    return(NDPI_PROTOCOL_LLMNR);
  case MDNS_PORT:
    return(NDPI_PROTOCOL_MDNS);
  }

  return(0);
}

/* *********************************************** */

static int isMDNSMulticastAddress(struct ndpi_packet_struct * const packet)
{
  return (packet->iph && ntohl(packet->iph->daddr) == 0xE00000FB /* multicast: 224.0.0.251 */) ||
         (packet->iphv6 && ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0]) == 0xFF020000 &&
                           ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[1]) == 0x00000000 &&
                           ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[2]) == 0x00000000 &&
                           ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[3]) == 0x000000FB /* multicast: FF02::FB */);
}

static int isLLMNRMulticastAddress(struct ndpi_packet_struct *const packet)
{
  return (packet->iph && ntohl(packet->iph->daddr) == 0xE00000FC /* multicast: 224.0.0.252 */) ||
         (packet->iphv6 && ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0]) == 0xFF020000 &&
                           ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[1]) == 0x00000000 &&
                           ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[2]) == 0x00000000 &&
                           ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[3]) == 0x00010003 /* multicast: FF02::1:3 */);
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

static u_int16_t get16(u_int *i, const u_int8_t *payload) {
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
  else if((payload[i] & 0xC0)== 0xC0)
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
  See
  - RFC 1035
  - https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/naming-conventions-for-computer-domain-site-ou
  
  Allowed chars for dns names A-Z 0-9 _ -
  Perl script for generation map:
  my @M;
  for(my $ch=0; $ch < 256; $ch++) {
  $M[$ch >> 5] |= 1 << ($ch & 0x1f) if chr($ch) =~ /[a-z0-9_-]/i;
  }
  print join(',', map { sprintf "0x%08x",$_ } @M),"\n";
*/

static uint32_t dns_validchar[8] = {
  0x00000000,0x03ff2000,0x87fffffe,0x07fffffe,0,0,0,0
};

/* *********************************************** */

static char* dns_error_code2string(u_int16_t error_code, char *buf, u_int buf_len) {
  switch(error_code) {
  case 1: return((char*)"FORMERR");
  case 2: return((char*)"SERVFAIL");
  case 3: return((char*)"NXDOMAIN");
  case 4: return((char*)"NOTIMP");
  case 5: return((char*)"REFUSED");
  case 6: return((char*)"YXDOMAIN");
  case 7: return((char*)"XRRSET");
  case 8: return((char*)"NOTAUTH");
  case 9: return((char*)"NOTZONE");

  default:
    snprintf(buf, buf_len, "%u", error_code);
    return(buf);
  }
}

/* *********************************************** */

u_int64_t fpc_dns_cache_key_from_flow(struct ndpi_flow_struct *flow) {
  u_int64_t key;

  if(flow->is_ipv6)
    key = ndpi_quick_hash64((const char *)flow->s_address.v6, 16);
  else
    key = (u_int64_t)(flow->s_address.v4);

  return key;
}

/* *********************************************** */

static u_int64_t fpc_dns_cache_key_from_packet(const unsigned char *ip, int ip_len) {
  u_int64_t key;

  if(ip_len == 16)
    key = ndpi_quick_hash64((const char *)ip, 16);
  else
    key = (u_int64_t)(*(u_int32_t *)ip);

  return key;
}

/* *********************************************** */

static u_int8_t ndpi_grab_dns_name(struct ndpi_packet_struct *packet,
				   u_int *off /* payload offset */,
				   char *_hostname, u_int max_len,
				   u_int *_hostname_len,
				   u_int8_t ignore_checks) {
  u_int8_t hostname_is_valid = 1;
  u_int j = 0;

  max_len--;

  while((j < max_len)
	&& ((*off) < packet->payload_packet_len)
	&& (packet->payload[(*off)] != '\0')) {
    u_int8_t c, cl = packet->payload[*off];

    if(((cl & 0xc0) != 0) || // we not support compressed names in query
       (((*off)+1) + cl  >= packet->payload_packet_len)) {
      /* Don't update the offset */
      j = 0;
      break;
    }

    (*off)++;

    if(j && (j < max_len)) _hostname[j++] = '.';

    while((j < max_len) && (cl != 0)) {
      c = packet->payload[(*off)++];

      if(ignore_checks)
	_hostname[j++] = tolower(c);
      else {
	u_int32_t shift;
      
	shift = ((u_int32_t) 1) << (c & 0x1f);

	if((dns_validchar[c >> 5] & shift)) {
	  _hostname[j++] = tolower(c);
	} else {
	  /* printf("---?? '%c'\n", c); */
	  
	  hostname_is_valid = 0;
	  
	  if (ndpi_isprint(c) == 0) {
	    _hostname[j++] = '?';
	  } else {
	    _hostname[j++] = '_';
	  }
	}
      }
      
      cl--;
    }
  }

  _hostname[j] = '\0', *_hostname_len = j;

  return(hostname_is_valid);
}

/* *********************************************** */

static int process_queries(struct ndpi_detection_module_struct *ndpi_struct,
                           struct ndpi_flow_struct *flow,
                           struct ndpi_dns_packet_header *dns_header,
                           u_int payload_offset) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int x = payload_offset;
  u_int16_t rsp_type;
  u_int16_t num;

  for(num = 0; num < dns_header->num_queries; num++) {
    u_int16_t data_len;

    if((data_len = getNameLength(x, packet->payload,
                                 packet->payload_packet_len)) == 0) {
      return -1;
    } else
      x += data_len;

    if(data_len > 253)
      ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid DNS Query Lenght");

    if((x+4) > packet->payload_packet_len) {
      ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid DNS Query Lenght");
      return -1;
    }

    rsp_type = get16(&x, packet->payload);

#ifdef DNS_DEBUG
    printf("[DNS] [response (query)] response_type=%d\n", rsp_type);
#endif
    if(flow->protos.dns.query_type == 0) {
      /* In case we missed the query packet... */
      flow->protos.dns.query_type = rsp_type;
    }

    /* here x points to the response "class" field */
    x += 2; /* Skip class */
  }

  return x;
}

static int process_answers(struct ndpi_detection_module_struct *ndpi_struct,
                           struct ndpi_flow_struct *flow,
                           struct ndpi_dns_packet_header *dns_header,
                           u_int payload_offset,
                           ndpi_master_app_protocol *proto) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int x = payload_offset;
  u_int16_t rsp_type;
  u_int32_t rsp_ttl;
  u_int16_t num;
  u_int8_t found = 0;
  int ignore_checks;

  ignore_checks = (proto->master_protocol == NDPI_PROTOCOL_MDNS);

  for(num = 0; num < dns_header->num_answers; num++) {
    u_int16_t data_len;

    if((data_len = getNameLength(x, packet->payload,
                                 packet->payload_packet_len)) == 0) {
      return -1;
    } else
      x += data_len;

    if((x+8) >= packet->payload_packet_len) {
      return -1;
    }

    rsp_type = get16(&x, packet->payload);
    rsp_ttl  = ntohl(*((u_int32_t*)&packet->payload[x+2]));

    if(rsp_ttl == 0)
      ndpi_set_risk(ndpi_struct, flow, NDPI_MINOR_ISSUES, "DNS Record with zero TTL");

#ifdef DNS_DEBUG
    printf("[DNS] Date len %u; TTL = %u\n", data_len, rsp_ttl);
    printf("[DNS] [response] response_type=%d\n", rsp_type);
#endif

    if(found == 0) {
      ndpi_check_dns_type(ndpi_struct, flow, rsp_type);
      flow->protos.dns.rsp_type = rsp_type;
    }

    /* x points to the response "class" field */
    if((x+12) <= packet->payload_packet_len) {
      u_int32_t ttl = ntohl(*((u_int32_t*)&packet->payload[x+2]));

      x += 6;
      data_len = get16(&x, packet->payload);

      if((x + data_len) <= packet->payload_packet_len) {
#ifdef DNS_DEBUG
        printf("[DNS] [rsp_type: %u][data_len: %u]\n", rsp_type, data_len);
#endif

        if(rsp_type == 0x05 /* CNAME */) {
          ;
        } else if(rsp_type == 0x0C /* PTR */) {
          u_int16_t ptr_len = (packet->payload[x-2] << 8) + packet->payload[x-1];

          if((x + ptr_len) <= packet->payload_packet_len) {
            if(found == 0) {
              u_int len, orig_x;

              orig_x = x;
              ndpi_grab_dns_name(packet, &x,
                                 flow->protos.dns.ptr_domain_name,
                                 sizeof(flow->protos.dns.ptr_domain_name), &len,
                                 ignore_checks);
              /* ndpi_grab_dns_name doesn't update the offset if it failed.
                 We unconditionally update it at the end of the for loop */
              x = orig_x;
              found = 1;
            }
          }
        } else if((((rsp_type == 0x1) && (data_len == 4)) /* A */
                   || ((rsp_type == 0x1c) && (data_len == 16)) /* AAAA */
                   )) {
          if(found == 0) {

            if(flow->protos.dns.num_rsp_addr < MAX_NUM_DNS_RSP_ADDRESSES) {
              /* Necessary for IP address comparison */
              memset(&flow->protos.dns.rsp_addr[flow->protos.dns.num_rsp_addr], 0, sizeof(ndpi_ip_addr_t));

              memcpy(&flow->protos.dns.rsp_addr[flow->protos.dns.num_rsp_addr], packet->payload + x, data_len);
              flow->protos.dns.is_rsp_addr_ipv6[flow->protos.dns.num_rsp_addr] = (data_len == 16) ? 1 : 0;
              flow->protos.dns.rsp_addr_ttl[flow->protos.dns.num_rsp_addr] = ttl;

              if(ndpi_struct->cfg.address_cache_size)
                ndpi_cache_address(ndpi_struct,
                                   flow->protos.dns.rsp_addr[flow->protos.dns.num_rsp_addr],
                                   flow->host_server_name,
                                   packet->current_time_ms/1000,
                                   flow->protos.dns.rsp_addr_ttl[flow->protos.dns.num_rsp_addr]);

              ++flow->protos.dns.num_rsp_addr;
            }

            if(flow->protos.dns.num_rsp_addr >= MAX_NUM_DNS_RSP_ADDRESSES)
              found = 1;
          }

          /* Add to FPC DNS cache */
          if(flow->protos.dns.num_rsp_addr == 1 && /* Only the first one */
             ndpi_struct->cfg.fpc_enabled &&
             proto->app_protocol != NDPI_PROTOCOL_UNKNOWN &&
             proto->app_protocol != proto->master_protocol &&
             ndpi_struct->fpc_dns_cache) {
            ndpi_lru_add_to_cache(ndpi_struct->fpc_dns_cache,
                                  fpc_dns_cache_key_from_packet(packet->payload + x, data_len),
                                  proto->app_protocol,
                                  ndpi_get_current_time(flow));
          }
        }

        x += data_len;
      }
    }

    if(found && (dns_header->additional_rrs == 0)) {
      /*
        In case we have RR we need to iterate
        all the answers and not just consider the
        first one as we need to properly move 'x'
        to the right offset
      */
      break;
    }
  }

  return x;
}

static int process_additionals(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow,
                               struct ndpi_dns_packet_header *dns_header,
                               u_int payload_offset) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int x = payload_offset;

  /*
    Dissect the rest of the packet only if there are
    additional_rrs as we need to check for:
     * EDNS(0)
     * NSID

    In this case we need to go through the whole packet
    as we need to update the 'x' offset
  */

  if(dns_header->additional_rrs == 0)
    return x;

  if(dns_header->authority_rrs > 0) {
#ifdef DNS_DEBUG
    u_int16_t rsp_type;
#endif
    u_int16_t num;

    for(num = 0; num < dns_header->authority_rrs; num++) {
      u_int16_t data_len;

      if((x+6) >= packet->payload_packet_len) {
        return -1;
      }

      if((data_len = getNameLength(x, packet->payload,
                                   packet->payload_packet_len)) == 0) {
        return -1;
      } else
        x += data_len;

      if((x+8) >= packet->payload_packet_len) {
        return -1;
      }

      /* To avoid warning: variable ‘rsp_type’ set but not used [-Wunused-but-set-variable] */
#ifdef DNS_DEBUG
      rsp_type = get16(&x, packet->payload);
#else
      get16(&x, packet->payload);
#endif

#ifdef DNS_DEBUG
      printf("[DNS] [RRS response] response_type=%d\n", rsp_type);
#endif

      /* here x points to the response "class" field */
      if((x+12) <= packet->payload_packet_len) {
        x += 6;
        data_len = get16(&x, packet->payload);

        if((x + data_len) <= packet->payload_packet_len)
          x += data_len;
      }
    }
  }

  if(dns_header->additional_rrs > 0) {
    u_int16_t rsp_type;
    u_int16_t num;

    for(num = 0; num < dns_header->additional_rrs; num++) {
      u_int16_t data_len, rdata_len, opt_code, opt_len;
      const unsigned char *opt;

#ifdef DNS_DEBUG
      printf("[DNS] [RR response %d/%d]\n", num + 1, dns_header->additional_rrs);
#endif

      if((x+6) > packet->payload_packet_len) {
        return -1;
      }

      if((data_len = getNameLength(x, packet->payload, packet->payload_packet_len)) == 0) {
        return -1;
      } else
        x += data_len;

      if((x+10) > packet->payload_packet_len) {
        return -1;
      }

      rsp_type = get16(&x, packet->payload);

#ifdef DNS_DEBUG
      printf("[DNS] [RR response] response_type=%d\n", rsp_type);
#endif

      if(rsp_type == 41 /* OPT */) {
        /* https://en.wikipedia.org/wiki/Extension_Mechanisms_for_DNS */
        flow->protos.dns.edns0_udp_payload_size = ntohs(*((u_int16_t*)&packet->payload[x])); /* EDNS(0) */

#ifdef DNS_DEBUG
        printf("[DNS] [response] edns0_udp_payload_size: %u\n", flow->protos.dns.edns0_udp_payload_size);
#endif
        x += 6;

        rdata_len = ntohs(*((u_int16_t *)&packet->payload[x]));
#ifdef DNS_DEBUG
        printf("[DNS] [response] rdata len: %u\n", rdata_len);
#endif
        if(rdata_len > 0 &&
           x + 6 <= packet->payload_packet_len) {
          opt_code = ntohs(*((u_int16_t *)&packet->payload[x + 2]));
          opt_len = ntohs(*((u_int16_t *)&packet->payload[x + 4]));
          opt = &packet->payload[x + 6];
          /* TODO: parse the TLV list */
          if(opt_code == 0x03 &&
             opt_len <= rdata_len + 4 &&
             opt_len > 6 &&
             x + 6 + opt_len <= packet->payload_packet_len) {
#ifdef DNS_DEBUG
            printf("[DNS] NSID: [%.*s]\n", opt_len, opt);
#endif
            if(memcmp(opt, "gpdns-", 6) == 0) {
#ifdef DNS_DEBUG
              printf("[DNS] NSID Airport code [%.*s]\n", opt_len - 6, opt + 6);
#endif
              memcpy(flow->protos.dns.geolocation_iata_code, opt + 6,
                     ndpi_min(opt_len - 6, (int)sizeof(flow->protos.dns.geolocation_iata_code) - 1));
            }
          }

        }
      } else {
        x += 6;
      }

      if((data_len = getNameLength(x, packet->payload, packet->payload_packet_len)) == 0) {
        return -1;
      } else
        x += data_len;
    }
  }

  return x;
}

static int is_valid_dns(struct ndpi_detection_module_struct *ndpi_struct,
			struct ndpi_flow_struct *flow,
			struct ndpi_dns_packet_header *dns_header,
			u_int payload_offset, u_int8_t *is_query) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int x = payload_offset;

  if(packet->payload_packet_len < sizeof(struct ndpi_dns_packet_header) + payload_offset)
    return 0;

  memcpy(dns_header, (struct ndpi_dns_packet_header*)&packet->payload[x],
	 sizeof(struct ndpi_dns_packet_header));

  dns_header->tr_id = ntohs(dns_header->tr_id);
  dns_header->flags = ntohs(dns_header->flags);
  dns_header->num_queries = ntohs(dns_header->num_queries);
  dns_header->num_answers = ntohs(dns_header->num_answers);
  dns_header->authority_rrs = ntohs(dns_header->authority_rrs);
  dns_header->additional_rrs = ntohs(dns_header->additional_rrs);

  x += sizeof(struct ndpi_dns_packet_header);

  if((dns_header->flags & FLAGS_MASK) == 0x0000)
    *is_query = 1;
  else
    *is_query = 0;

  if(*is_query) {
    if(dns_header->num_queries <= NDPI_MAX_DNS_REQUESTS &&
       /* dns_header->num_answers == 0 && */
       ((dns_header->flags & 0x2800) == 0x2800 /* Dynamic DNS Update */ ||
	(dns_header->flags & 0xFCF0) == 0x00 /* Standard Query */ ||
	(dns_header->flags & 0xFCFF) == 0x0800 /* Inverse query */ ||
	(dns_header->num_answers == 0 && dns_header->authority_rrs == 0))) {
      /* This is a good query */
      return 1;
    }
  } else {
    if(((dns_header->num_queries > 0 && dns_header->num_queries <= NDPI_MAX_DNS_REQUESTS) || /* Don't assume that num_queries must be zero */
        (checkDNSSubprotocol(ntohs(flow->c_port), ntohs(flow->s_port)) == NDPI_PROTOCOL_MDNS && dns_header->num_queries == 0)) &&
       ((dns_header->num_answers > 0 && dns_header->num_answers <= NDPI_MAX_DNS_REQUESTS) ||
        (dns_header->authority_rrs > 0 && dns_header->authority_rrs <= NDPI_MAX_DNS_REQUESTS) ||
        (dns_header->additional_rrs > 0 && dns_header->additional_rrs <= NDPI_MAX_DNS_REQUESTS) ||
        (dns_header->num_answers == 0 && dns_header->authority_rrs == 0 && dns_header->additional_rrs == 0))) {
      /* This is a good reply */
      return 1;
    }
    if(dns_header->num_queries == 0 && dns_header->num_answers == 0 &&
       dns_header->authority_rrs == 0 && dns_header->additional_rrs == 0 &&
       packet->payload_packet_len == sizeof(struct ndpi_dns_packet_header)) {
      /* This is a good empty reply */
      return 1;
    }
  }
  return 0;
}

/* *********************************************** */

static int keep_extra_dissection(struct ndpi_flow_struct *flow)
{
  /* As a general rule, we wait for a valid response
     (in the ideal world, we want to process the request/response pair) */
  return !(!flow->protos.dns.is_query && flow->protos.dns.num_answers != 0);
}

/* *********************************************** */

static int search_dns_again(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(packet->tcp_retransmission || packet->payload_packet_len == 0)
    return keep_extra_dissection(flow);

  /* possibly dissect the DNS reply */
  search_dns(ndpi_struct, flow);

  return keep_extra_dissection(flow);
}

/* *********************************************** */

static int process_hostname(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow,
                            struct ndpi_dns_packet_header *dns_header,
                            ndpi_master_app_protocol *proto) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  char *dot;
  u_int len, is_mdns, off = sizeof(struct ndpi_dns_packet_header) + (packet->tcp ? 2 : 0);
  char _hostname[256];
  u_int8_t hostname_is_valid;

  proto->master_protocol = checkDNSSubprotocol(ntohs(flow->c_port), ntohs(flow->s_port));
  proto->app_protocol = NDPI_PROTOCOL_UNKNOWN;

  /* We try to get hostname only from "standard" query/answer */
  if(dns_header->num_queries == 0 && dns_header->num_answers == 0)
    return -1;

  is_mdns = (proto->master_protocol == NDPI_PROTOCOL_MDNS);

  /* TODO: should we overwrite existing hostname?
     For the time being, keep the old/current behavior */

  hostname_is_valid = ndpi_grab_dns_name(packet, &off, _hostname, sizeof(_hostname), &len, is_mdns);

#ifdef DNS_DEBUG
  printf("[DNS] [%s]\n", _hostname);
#endif

  ndpi_hostname_sni_set(flow, (const u_int8_t *)_hostname, len, is_mdns ? NDPI_HOSTNAME_NORM_LC : NDPI_HOSTNAME_NORM_ALL);

  if (hostname_is_valid == 0)
    ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, "Invalid chars detected in domain name");

  /* Ignore reverse DNS queries */
  if(strstr(_hostname, ".in-addr.") == NULL) {
    dot = strchr(_hostname, '.');

    if(dot) {
      uintptr_t first_element_len = dot - _hostname;

      if((first_element_len > 48) && (!is_mdns)) {
        /*
          The length of the first element in the query is very long
          and this might be an issue or indicate an exfiltration
        */

        if(ends_with(ndpi_struct, _hostname, "multi.surbl.org")
           || ends_with(ndpi_struct, _hostname, "spamhaus.org")
           || ends_with(ndpi_struct, _hostname, "rackcdn.com")
           || ends_with(ndpi_struct, _hostname, "akamaiedge.net")
           || ends_with(ndpi_struct, _hostname, "mx-verification.google.com")
           || ends_with(ndpi_struct, _hostname, "amazonaws.com")
           )
          ; /* Check common domain exceptions [TODO: if the list grows too much use a different datastructure] */
        else
          ndpi_set_risk(ndpi_struct, flow, NDPI_DNS_SUSPICIOUS_TRAFFIC, "Long DNS host name");
      }
    }
  }

  if(strlen(flow->host_server_name) > 0) {
    ndpi_protocol_match_result ret_match;

    /* Avoid updating classification if subclassification is disabled */
    proto->app_protocol = ndpi_match_host_subprotocol(ndpi_struct, flow,
                                                      flow->host_server_name,
                                                      strlen(flow->host_server_name),
                                                      &ret_match,
                                                      proto->master_protocol,
                                                      ndpi_struct->cfg.dns_subclassification_enabled ? 1 : 0);

    ndpi_check_dga_name(ndpi_struct, flow, flow->host_server_name, 1, 0, proto->app_protocol != NDPI_PROTOCOL_UNKNOWN);
  }

  return 0;
}

static void search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int payload_offset = 0;
  u_int8_t is_query;
  struct ndpi_dns_packet_header dns_header;
  u_int off;
  ndpi_master_app_protocol proto;
  int rc;

  if(packet->udp != NULL) {
    payload_offset = 0;
  } else if(packet->tcp != NULL) {
    payload_offset = 2;
  }

  if(!is_valid_dns(ndpi_struct, flow, &dns_header, payload_offset, &is_query)) {
#ifdef DNS_DEBUG
    printf("[DNS] invalid packet\n");
#endif
    if(flow->extra_packets_func == NULL) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    } else {
      ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid DNS Header");
    }
    return;
  }

  process_hostname(ndpi_struct, flow, &dns_header, &proto);

  off = sizeof(struct ndpi_dns_packet_header) + payload_offset;

  if(is_query) {
    flow->protos.dns.is_query = 1;
    flow->protos.dns.transaction_id = dns_header.tr_id;

    rc = process_queries(ndpi_struct, flow, &dns_header, off);
#ifdef DNS_DEBUG
    if(rc == -1)
      printf("[DNS] Error queries (query msg)\n");
#endif
  } else {
    flow->protos.dns.is_query = 0;
    flow->protos.dns.transaction_id = dns_header.tr_id;
    flow->protos.dns.reply_code = dns_header.flags & 0x0F;
    flow->protos.dns.num_queries = dns_header.num_queries;
    flow->protos.dns.num_answers = dns_header.num_answers + dns_header.authority_rrs + dns_header.additional_rrs;

    if(flow->protos.dns.reply_code != 0) {
      char str[32], buf[16];

      snprintf(str, sizeof(str), "DNS Error Code %s",
               dns_error_code2string(flow->protos.dns.reply_code, buf, sizeof(buf)));
      ndpi_set_risk(ndpi_struct, flow, NDPI_ERROR_CODE_DETECTED, str);
    } else {
      if(ndpi_isset_risk(flow, NDPI_SUSPICIOUS_DGA_DOMAIN)) {
        ndpi_set_risk(ndpi_struct, flow, NDPI_RISKY_DOMAIN, "DGA Name Query with no Error Code");
      }
    }

    rc = process_queries(ndpi_struct, flow, &dns_header, off);
    if(rc == -1) {
#ifdef DNS_DEBUG
      printf("[DNS] Error queries (response msg)\n");
#endif
    } else {
      off = rc;
      rc = process_answers(ndpi_struct, flow, &dns_header, off, &proto);
      if(rc == -1) {
#ifdef DNS_DEBUG
        printf("[DNS] Error answers\n");
#endif
      } else {
        off = rc;
        rc = process_additionals(ndpi_struct, flow, &dns_header, off);
#ifdef DNS_DEBUG
        if(rc == -1)
          printf("[DNS] Error additionals\n");
#endif
      }
    }

    if(proto.master_protocol == NDPI_PROTOCOL_DNS &&
      /* TODO: add support to RFC6891 to avoid some false positives */
       packet->udp &&
       packet->payload_packet_len > PKT_LEN_ALERT &&
       packet->payload_packet_len > flow->protos.dns.edns0_udp_payload_size) {
      char str[48];

      snprintf(str, sizeof(str), "%u Bytes DNS Packet", packet->payload_packet_len);
      ndpi_set_risk(ndpi_struct, flow, NDPI_DNS_LARGE_PACKET, str);
    }

    NDPI_LOG_DBG2(ndpi_struct, "Response: [num_queries=%d][num_answers=%d][reply_code=%u][rsp_type=%u][host_server_name=%s]\n",
                  flow->protos.dns.num_queries, flow->protos.dns.num_answers,
                  flow->protos.dns.reply_code, flow->protos.dns.rsp_type, flow->host_server_name);
  }

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
    if(ndpi_struct->cfg.dns_subclassification_enabled)
      ndpi_set_detected_protocol(ndpi_struct, flow, proto.app_protocol, proto.master_protocol, NDPI_CONFIDENCE_DPI);
    else
      ndpi_set_detected_protocol(ndpi_struct, flow, proto.master_protocol, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  }
  /* Category is always NDPI_PROTOCOL_CATEGORY_NETWORK, regardless of the subprotocol */
  flow->category = NDPI_PROTOCOL_CATEGORY_NETWORK;

  if(!flow->extra_packets_func &&
     ndpi_struct->cfg.dns_parse_response_enabled &&
     /* We have never triggered extra-dissection for LLMNR. Keep the old behavior */
     flow->detected_protocol_stack[0] != NDPI_PROTOCOL_LLMNR &&
     flow->detected_protocol_stack[1] != NDPI_PROTOCOL_LLMNR) {
    if(keep_extra_dissection(flow)) {
      NDPI_LOG_DBG(ndpi_struct, "Enabling extra dissection\n");
      flow->max_extra_packets_to_check = 5;
      flow->extra_packets_func = search_dns_again;
    }
  }

  /* The bigger packets are usually the replies, but it shouldn't harm
     to check the requests, too */
  if((flow->detected_protocol_stack[0] == NDPI_PROTOCOL_DNS)
     || (flow->detected_protocol_stack[1] == NDPI_PROTOCOL_DNS)) {

    if(packet->iph != NULL) {
      /* IPv4 */
      u_int8_t flags = ((u_int8_t*)packet->iph)[6];

      /* 0: fragmented; 1: not fragmented */
      if((flags & 0x20)
	 || (iph_is_valid_and_not_fragmented(packet->iph, packet->l3_packet_len) == 0)) {
	ndpi_set_risk(ndpi_struct, flow, NDPI_DNS_FRAGMENTED, NULL);
      }
    } else if(packet->iphv6 != NULL) {
      /* IPv6 */
      const struct ndpi_ip6_hdrctl *ip6_hdr = &packet->iphv6->ip6_hdr;

      if(ip6_hdr->ip6_un1_nxt == 0x2C /* Next Header: Fragment Header for IPv6 (44) */) {
	ndpi_set_risk(ndpi_struct, flow, NDPI_DNS_FRAGMENTED, NULL);
      }
    }
  }
}

/* *********************************************** */

static void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t s_port = 0, d_port = 0;
  int payload_offset = 0;

  NDPI_LOG_DBG(ndpi_struct, "search DNS\n");

  if(packet->udp != NULL) {
    s_port = ntohs(packet->udp->source);
    d_port = ntohs(packet->udp->dest);
    payload_offset = 0;

    /* For MDNS/LLMNR: If the packet is not a response, dest addr needs to be multicast. */
    if ((d_port == MDNS_PORT && isMDNSMulticastAddress(packet) == 0) ||
        (d_port == LLMNR_PORT && isLLMNRMulticastAddress(packet) == 0))
    {
      if (packet->payload_packet_len > 5 &&
          ntohs(get_u_int16_t(packet->payload, 2)) != 0 &&
          ntohs(get_u_int16_t(packet->payload, 4)) != 0)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }
    }
  } else if(packet->tcp != NULL) {
    s_port = ntohs(packet->tcp->source);
    d_port = ntohs(packet->tcp->dest);
    payload_offset = 2;
  }

  /* We are able to detect DNS/MDNS/LLMNR only on standard ports (see #1788) */
  if(!(s_port == DNS_PORT || d_port == DNS_PORT ||
       s_port == MDNS_PORT || d_port == MDNS_PORT ||
       d_port == LLMNR_PORT)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /* Since:
      UDP: every packet must contains a complete/valid DNS message;
      TCP: we are not able to handle DNS messages spanning multiple TCP packets;
     we must be able to detect these protocols on the first packet
  */
  if(packet->payload_packet_len < sizeof(struct ndpi_dns_packet_header) + payload_offset) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  search_dns(ndpi_struct, flow);
}

/* *********************************************** */

void init_dns_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("DNS", ndpi_struct, *id,
				      NDPI_PROTOCOL_DNS,
				      ndpi_search_dns,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;

}
