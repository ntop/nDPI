/*
 * ethereum.c 
 *
 * Copyright (C) 2023 by ntop.org
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
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ETHEREUM
#include "ndpi_api.h"


/* ************************************************************************** */

static u_int32_t ndpi_ether_make_lru_cache_key(struct ndpi_flow_struct *flow) {
  u_int32_t key;

  /* network byte order */
  if(flow->is_ipv6)
    key = ndpi_quick_hash(flow->c_address.v6, 16) + ndpi_quick_hash(flow->s_address.v6, 16);
  else
    key = flow->c_address.v4 + flow->s_address.v4;

  return key;
}

/* ************************************************************************** */

static void ndpi_ether_cache_connection(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  if(ndpi_struct->mining_cache)
    ndpi_lru_add_to_cache(ndpi_struct->mining_cache, ndpi_ether_make_lru_cache_key(flow), NDPI_PROTOCOL_ETHEREUM, ndpi_get_current_time(flow));
}

/* ************************************************************************** */

static void ndpi_search_ethereum_udp(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t source = ntohs(packet->udp->source);
  u_int16_t dest = ntohs(packet->udp->dest);

  NDPI_LOG_DBG(ndpi_struct, "search ETHEREUM UDP\n");

  /* 
     Ethereum P2P Discovery Protocol
     https://github.com/ConsenSys/ethereum-dissectors/blob/master/packet-ethereum-disc.c
  */
  if((packet->payload_packet_len > 98)
     && (packet->payload_packet_len < 1280)
     && ((source == 30303) || (dest == 30303))
     && (packet->payload[97] <= 0x04 /* NODES */)
     ) {
    if((packet->iph) && ((ntohl(packet->iph->daddr) & 0xFF000000 /* 255.0.0.0 */) == 0xFF000000))
      ;
    else if(packet->iphv6 && ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0]) == 0xFF020000)
      ;
    else {
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ETHEREUM, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      ndpi_ether_cache_connection(ndpi_struct, flow);
      return;
    }
  }
  
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ************************************************************************** */

static u_int8_t ndpi_is_ether_port(u_int16_t dport) {
  return(((dport >= 30300) && (dport <= 30305)) ? 1 : 0);
}

/* ************************************************************************** */

static void ndpi_search_ethereum_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search ETHEREUM TCP\n");

  /* Check connection over TCP */
  if(packet->payload_packet_len > 10) {
    if((packet->payload_packet_len > 300)
       && (packet->payload_packet_len < 600)
       && (packet->payload[2] == 0x04)) {
      if(ndpi_is_ether_port(ntohs(packet->tcp->dest)) /* Ethereum port */) {
	      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ETHEREUM, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
	      ndpi_ether_cache_connection(ndpi_struct, flow);
	      return;
      } 
    } else if(ndpi_strnstr((const char *)packet->payload, "{", packet->payload_packet_len)
	 && (
	   ndpi_strnstr((const char *)packet->payload, "\"eth1.0\"", packet->payload_packet_len)
	   || ndpi_strnstr((const char *)packet->payload, "\"worker\":", packet->payload_packet_len)
	   /* || ndpi_strnstr((const char *)packet->payload, "\"id\":", packet->payload_packet_len) - Removed as too generic */
	   )) {
      /*
	Ethereum
	
	{"worker": "eth1.0", "jsonrpc": "2.0", "params": ["0x0fccfff9e61a230ff380530c6827caf4759337c6.rig2", "x"], "id": 2, "method": "eth_submitLogin"}
	{ "id": 2, "jsonrpc":"2.0","result":true}
	{"worker": "", "jsonrpc": "2.0", "params": [], "id": 3, "method": "eth_getWork"}
      */
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ETHEREUM, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      ndpi_ether_cache_connection(ndpi_struct, flow);
      return;
    } 
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ************************************************************************** */

static void ndpi_search_ethereum(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(packet->tcp)
    return ndpi_search_ethereum_tcp(ndpi_struct, flow);
  return ndpi_search_ethereum_udp(ndpi_struct, flow);
}


/* ************************************************************************** */

void init_ethereum_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			   u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Ethereum", ndpi_struct, *id,
				      NDPI_PROTOCOL_ETHEREUM,
				      ndpi_search_ethereum,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

