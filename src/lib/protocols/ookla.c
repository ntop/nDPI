/*
 * ookla.c
 *
 * Copyright (C) 2018-21 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_OOKLA

#include "ndpi_api.h"

const u_int16_t ookla_port = 8080;

/* ************************************************************* */

void ndpi_search_ookla(struct ndpi_detection_module_struct* ndpi_struct, struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &flow->packet;
  u_int32_t addr = 0;
  u_int16_t sport, dport;
    
  NDPI_LOG_DBG(ndpi_struct, "Ookla detection\n");

  if(packet->tcp)
    sport = ntohs(packet->tcp->source), dport = htons(packet->tcp->dest);
  else
    sport = ntohs(packet->udp->source), dport = htons(packet->udp->dest);

  if((sport != ookla_port) && (dport != ookla_port)) {
#ifdef OOKLA_DEBUG
    printf("=>>>>>>>> [OOKLA IPv6] Skipping flow [%u -> %u]\n", sport, dport);
#endif
    goto ookla_exclude;
  }
  
  if(packet->iphv6 != NULL) {
    if((dport == ookla_port) && (packet->payload_packet_len >= 3)) {
      u_int32_t h;
      
      if((packet->payload_packet_len == 3)
	 && (packet->payload[0] == 0x48) /* HI\n */
	 && (packet->payload[1] == 0x49)
	 && (packet->payload[2] == 0x0A)) {	
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_UNKNOWN);
	
	if(ndpi_struct->ookla_cache == NULL)
	  ndpi_struct->ookla_cache = ndpi_lru_cache_init(1024);
	
	if(ndpi_struct->ookla_cache != NULL) {
	  /* In order to avoid creating an IPv6 LRU we hash the IPv6 address */
	  h = ndpi_quick_hash((unsigned char *)&packet->iphv6->ip6_dst, sizeof(packet->iphv6->ip6_dst));

#ifdef OOKLA_DEBUG
	  printf("=>>>>>>>> [OOKLA IPv6] Adding %u\n", h);
#endif
	  ndpi_lru_add_to_cache(ndpi_struct->ookla_cache, h, 1 /* dummy */);
	}
	return;
      } else {
	if(sport == ookla_port)
	  h = ndpi_quick_hash((unsigned char *)&packet->iphv6->ip6_src, sizeof(packet->iphv6->ip6_src));
	else
	  h = ndpi_quick_hash((unsigned char *)&packet->iphv6->ip6_dst, sizeof(packet->iphv6->ip6_dst));
	
	if(ndpi_struct->ookla_cache != NULL) {
	  u_int16_t dummy;

#ifdef OOKLA_DEBUG
	  printf("=>>>>>>>> [OOKLA IPv6] Searching %u\n", h);
#endif
	  
	  if(ndpi_lru_find_cache(ndpi_struct->ookla_cache, h, &dummy, 0 /* Don't remove it as it can be used for other connections */)) {
	    NDPI_LOG_INFO(ndpi_struct, "found ookla tcp connection\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_UNKNOWN);
#ifdef OOKLA_DEBUG
	    printf("=>>>>> Found %u\n", h);
#endif
	    return;
	  } else {
#ifdef OOKLA_DEBUG
	    printf("=>>>>> NOT Found %u\n", h);
#endif
	  }
	}
      }
    } else {

      goto ookla_exclude;
    }
  } else {
    if(sport == ookla_port)
      addr = packet->iph->saddr;
    else if(dport == ookla_port)
      addr = packet->iph->daddr;
    else
      goto ookla_exclude;

#ifdef OOKLA_DEBUG
    printf("=>>>>>>>> [OOKLA IPv4] Searching %u\n", addr);
#endif
    
    if(ndpi_struct->ookla_cache != NULL) {
      u_int16_t dummy;
    
      if(ndpi_lru_find_cache(ndpi_struct->ookla_cache, addr, &dummy, 0 /* Don't remove it as it can be used for other connections */)) {
	NDPI_LOG_INFO(ndpi_struct, "found ookla tcp connection\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_UNKNOWN);
#ifdef OOKLA_DEBUG
	printf("=>>>>> Found %u\n", addr);
#endif
	return;
      } else {
#ifdef OOKLA_DEBUG
	printf("=>>>>> NOT Found %u\n", addr);
#endif
      }
    }
  }
  
 ookla_exclude:
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ************************************************************* */

void init_ookla_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			  u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("Ookla", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_OOKLA,
				      ndpi_search_ookla,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
