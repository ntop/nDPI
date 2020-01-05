/*
 * skype.c
 *
 * Copyright (C) 2017-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SKYPE

#include "ndpi_api.h"

static int is_port(u_int16_t a, u_int16_t b, u_int16_t c) {
  return(((a == c) || (b == c)) ? 1 : 0);
}

static void ndpi_check_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  // const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;

  /* No need to do ntohl() with 0xFFFFFFFF */
  if(packet->iph && (packet->iph->daddr == 0xFFFFFFFF /* 255.255.255.255 */)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if(flow->host_server_name[0] != '\0')
    return;
  
  // UDP check
  if(packet->udp != NULL) {    
    flow->l4.udp.skype_packet_id++;

    if(flow->l4.udp.skype_packet_id < 5) {
      u_int16_t sport = ntohs(packet->udp->source);
      u_int16_t dport = ntohs(packet->udp->dest);

      /* skype-to-skype */
      if(is_port(sport, dport, 1119) /* It can be confused with battle.net */
	 || is_port(sport, dport, 80) /* No HTTP-like protocols UDP/80 */
	 ) {
	;
      } else {
	/* Too many false positives */
	if(((payload_len == 3) && ((packet->payload[2] & 0x0F)== 0x0d))
	   ||
	   ((payload_len >= 16)
	    && (((packet->payload[0] & 0xC0) >> 6) == 0x02 /* RTPv2 */
		|| (((packet->payload[0] & 0xF0) >> 4) == 0 /* Zoom */)
		|| (((packet->payload[0] & 0xF0) >> 4) == 0x07 /* Skype */)
		)
	    && (packet->payload[0] != 0x30) /* Avoid invalid SNMP detection */
	    && (packet->payload[0] != 0x0)  /* Avoid invalid CAPWAP detection */
	    && (packet->payload[2] == 0x02))) {

	  if(is_port(sport, dport, 8801))
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZOOM, NDPI_PROTOCOL_UNKNOWN);
	  else
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE_CALL, NDPI_PROTOCOL_SKYPE);
	}
      }
      
      // return;
    }
    
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
    // TCP check
  } else if((packet->tcp != NULL)
	    /* As the TCP skype heuristic is weak, we need to make sure no other protocols overlap */
	    && (flow->guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN)
	    && (flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN)) {
    flow->l4.tcp.skype_packet_id++;

    if(flow->l4.tcp.skype_packet_id < 3) {
      ; /* Too early */
    } else if((flow->l4.tcp.skype_packet_id == 3)
	      /* We have seen the 3-way handshake */
	      && flow->l4.tcp.seen_syn
	      && flow->l4.tcp.seen_syn_ack
	      && flow->l4.tcp.seen_ack) {
      /* Disabled this logic as it's too weak and leads to false positives */
#if 0
      if((payload_len == 8) || (payload_len == 3) || (payload_len == 17)) {
	// printf("[SKYPE] payload_len=%u\n", payload_len);
	/* printf("[SKYPE] %u/%u\n", ntohs(packet->tcp->source), ntohs(packet->tcp->dest)); */
	
	NDPI_LOG_INFO(ndpi_struct, "found skype\n");
	  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE_CALL, NDPI_PROTOCOL_SKYPE);
      } else {
	// printf("NO [SKYPE] payload_len=%u\n", payload_len);
      }

      /* printf("[SKYPE] [id: %u][len: %d]\n", flow->l4.tcp.skype_packet_id, payload_len);  */
#endif
    } else {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }

    return;
  }
}

void ndpi_search_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search skype\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_SKYPE)
    ndpi_check_skype(ndpi_struct, flow);
}


void init_skype_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Skype", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SKYPE,
				      ndpi_search_skype,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
