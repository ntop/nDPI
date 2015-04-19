/*
 * skype.c
 *
 * Copyright (C) 2011-15 - ntop.org
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


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_SKYPE


static u_int8_t is_skype_host(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t host) {
  struct in_addr pin;
  
  pin.s_addr = host;
  
  return((ndpi_network_ptree_match(ndpi_struct, &pin) == NDPI_PROTOCOL_SKYPE) ? 1 : 0);
}

u_int8_t is_skype_flow(struct ndpi_detection_module_struct *ndpi_struct,
		       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
	
  if(packet->iph) {
    /*
      Skype connections are identified by some SSL-like communications
      without SSL certificate being exchanged
    */	
    if(is_skype_host(ndpi_struct, ntohl(packet->iph->saddr))
       || is_skype_host(ndpi_struct, ntohl(packet->iph->daddr))) {
      return(1);
    }
  }

  return(0);
}

static void ndpi_check_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  // const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;

  /*
    Skype AS8220
    212.161.8.0/24
  */
  if(is_skype_flow(ndpi_struct, flow)) {
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE, NDPI_REAL_PROTOCOL);
    return;
  }

  if(packet->udp != NULL) {
    flow->l4.udp.skype_packet_id++;

    if(flow->l4.udp.skype_packet_id < 5) {
      /* skype-to-skype */
      if(((payload_len == 3) && ((packet->payload[2] & 0x0F)== 0x0d))
	 || ((payload_len >= 16)
	     && (packet->payload[0] != 0x30) /* Avoid invalid SNMP detection */
	     && (packet->payload[2] == 0x02))) {
	NDPI_LOG(NDPI_PROTOCOL_SKYPE, ndpi_struct, NDPI_LOG_DEBUG, "Found skype.\n");
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE, NDPI_REAL_PROTOCOL);
      }

      return;
    }

    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SKYPE);
    return;
  } else if(packet->tcp != NULL) {
    flow->l4.tcp.skype_packet_id++;

    if(flow->l4.tcp.skype_packet_id < 3) {
      ; /* Too early */
    } else if((flow->l4.tcp.skype_packet_id == 3)
	      /* We have seen the 3-way handshake */
	      && flow->l4.tcp.seen_syn
	      && flow->l4.tcp.seen_syn_ack
	      && flow->l4.tcp.seen_ack) {
      if((payload_len == 8) || (payload_len == 3)) {
	//printf("[SKYPE] %u/%u\n", ntohs(packet->tcp->source), ntohs(packet->tcp->dest));

	NDPI_LOG(NDPI_PROTOCOL_SKYPE, ndpi_struct, NDPI_LOG_DEBUG, "Found skype.\n");
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE, NDPI_REAL_PROTOCOL);
      }

      /* printf("[SKYPE] [id: %u][len: %d]\n", flow->l4.tcp.skype_packet_id, payload_len);  */
    } else
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SKYPE);

    return;
  }
}

void ndpi_search_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_SKYPE, ndpi_struct, NDPI_LOG_DEBUG, "skype detection...\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_SKYPE)
    ndpi_check_skype(ndpi_struct, flow);
}

#endif
