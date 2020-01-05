/*
 * hangout.c
 *
 * Copyright (C) 2012-20 - ntop.org
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HANGOUT_DUO

/* #define DEBUG_LRU 1 */

#include "ndpi_api.h"

/* stun.c */
extern u_int32_t get_stun_lru_key(struct ndpi_flow_struct *flow);

/* https://support.google.com/a/answer/1279090?hl=en */
#define HANGOUT_UDP_LOW_PORT  19302
#define HANGOUT_UDP_HIGH_PORT 19309
#define HANGOUT_TCP_LOW_PORT  19305
#define HANGOUT_TCP_HIGH_PORT 19309

/* ***************************************************************** */

static u_int8_t isHangoutUDPPort(u_int16_t port) {
  if((port >= HANGOUT_UDP_LOW_PORT) && (port <= HANGOUT_UDP_HIGH_PORT))
    return(1);
  else
    return(0);
}

/* ***************************************************************** */

static u_int8_t isHangoutTCPPort(u_int16_t port) {
  if((port >= HANGOUT_TCP_LOW_PORT) && (port <= HANGOUT_TCP_HIGH_PORT))
    return(1);
  else
    return(0);
}

/* ******************************************* */

static u_int8_t google_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, struct in_addr *pin) {
  return((ndpi_network_ptree_match(ndpi_struct, pin) == NDPI_PROTOCOL_GOOGLE) ? 1 : 0);
}

/* ******************************************* */

static u_int8_t is_google_flow(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  
  if(packet->iph) {
    struct in_addr saddr, daddr;

    saddr.s_addr = packet->iph->saddr, daddr.s_addr = packet->iph->daddr;
    
    if(google_ptree_match(ndpi_struct, &saddr)
       || google_ptree_match(ndpi_struct, &daddr)) {
      return(1);
    }
  }

  return(0);
}

/* ***************************************************************** */

void ndpi_search_hangout(struct ndpi_detection_module_struct *ndpi_struct,
			 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct * packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Hangout\n");

  if((packet->payload_packet_len > 24) && is_google_flow(ndpi_struct, flow)) {
    if(
       ((packet->udp != NULL) && (isHangoutUDPPort(ntohs(packet->udp->source))
				  || isHangoutUDPPort(ntohs(packet->udp->dest))))
       ||
       ((packet->tcp != NULL) && (isHangoutTCPPort(ntohs(packet->tcp->source))
				  || isHangoutTCPPort(ntohs(packet->tcp->dest))))) {
      NDPI_LOG_INFO(ndpi_struct, "found Hangout\n");

      /* Hangout is over STUN hence the LRU cache is shared */
      if(ndpi_struct->stun_cache == NULL)
	ndpi_struct->stun_cache = ndpi_lru_cache_init(1024);

      if(ndpi_struct->stun_cache && flow->packet.iph && flow->packet.udp) {
	u_int32_t key = get_stun_lru_key(flow);
	
#ifdef DEBUG_LRU
	printf("[LRU] ADDING %u / %u.%u\n", key, NDPI_PROTOCOL_STUN, NDPI_PROTOCOL_HANGOUT_DUO);
#endif

	ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key, NDPI_PROTOCOL_HANGOUT_DUO);
      }
      
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HANGOUT_DUO,
				 NDPI_PROTOCOL_STUN);
      return;
    }
  }
  
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ***************************************************************** */

void init_hangout_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			    NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("GoogleHangout", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_HANGOUT_DUO,
				      ndpi_search_hangout,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

