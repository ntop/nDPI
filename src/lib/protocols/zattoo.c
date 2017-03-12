/*
 * zattoo.c
 *
 * Copyright (C) 2016 - ntop.org
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
#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_ZATTOO
	
#ifndef WIN32
static inline
#else
__forceinline static
#endif
u_int8_t ndpi_int_zattoo_user_agent_set(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  if(flow->packet.user_agent_line.ptr != NULL && flow->packet.user_agent_line.len == 111) {
    if(memcmp(flow->packet.user_agent_line.ptr + flow->packet.user_agent_line.len - 25, "Zattoo/4", sizeof("Zattoo/4") - 1) == 0) {
      NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "found zattoo useragent\n");
      return 1;
    }
  }
  return 0;
}

void ndpi_search_zattoo(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  u_int16_t i;

  if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_ZATTOO) {
    if(src != NULL && ((u_int32_t) (packet->tick_timestamp - src->zattoo_ts) < ndpi_struct->zattoo_connection_timeout))
      src->zattoo_ts = packet->tick_timestamp;
    if (dst != NULL && ((u_int32_t) (packet->tick_timestamp - dst->zattoo_ts) < ndpi_struct->zattoo_connection_timeout))
      dst->zattoo_ts = packet->tick_timestamp;
    return;
  }
  /* search over TCP */
  if(packet->tcp != NULL) {
    if(packet->payload_packet_len > 50 && memcmp(packet->payload, "GET /frontdoor/fd?brand=Zattoo&v=", 33) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "add connection over tcp with pattern GET /frontdoor/fd?brand=Zattoo&v=\n");

      if (src != NULL)
	src->zattoo_ts = packet->tick_timestamp;
      if (dst != NULL)
	dst->zattoo_ts = packet->tick_timestamp;
      
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
    if(packet->payload_packet_len > 50	&& memcmp(packet->payload, "GET /ZattooAdRedirect/redirect.jsp?user=", 40) == 0) {
      
      NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "add connection over tcp with pattern GET /ZattooAdRedirect/redirect.jsp?user=\n");

      if(src != NULL)
	src->zattoo_ts = packet->tick_timestamp;
      if(dst != NULL)
	dst->zattoo_ts = packet->tick_timestamp;
      
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
    if(packet->payload_packet_len > 50 && (memcmp(packet->payload, "POST /channelserver/player/channel/update HTTP/1.1", 50) == 0
					   || memcmp(packet->payload, "GET /epg/query", 14) == 0)) {
      
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      
      for(i = 0; i < packet->parsed_lines; i++) {
	if(packet->line[i].len >= 18 && (memcmp(packet->line[i].ptr, "User-Agent: Zattoo", 18) == 0)) {
	  
	  NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "add connection over tcp with pattern POST /channelserver/player/channel/update HTTP/1.1\n");
	  
	  if(src != NULL)
	    src->zattoo_ts = packet->tick_timestamp;
	  if(dst != NULL)
	    dst->zattoo_ts = packet->tick_timestamp;
	  
	  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_UNKNOWN);
	  return;
	}
      }
    } else if(packet->payload_packet_len > 50 && (memcmp(packet->payload, "GET /", 5) == 0 || memcmp(packet->payload, "POST /", NDPI_STATICSTRING_LEN("POST /")) == 0)) {
      /* TODO to avoid searching currently only a specific length and offset is used
       * that might be changed later */
      ndpi_parse_packet_line_info(ndpi_struct, flow);

      if(ndpi_int_zattoo_user_agent_set(ndpi_struct, flow)) {
	
	if(src != NULL)
	  src->zattoo_ts = packet->tick_timestamp;
	if(dst != NULL)
	  dst->zattoo_ts = packet->tick_timestamp;
	
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
    } else if(packet->payload_packet_len > 50 && memcmp(packet->payload, "POST http://", 12) == 0) {
      
      ndpi_parse_packet_line_info(ndpi_struct, flow);

      // test for unique character of the zattoo header
      if(packet->parsed_lines == 4 && packet->host_line.ptr != NULL) {
	u_int32_t ip;
	u_int16_t bytes_read = 0;

	ip = ndpi_bytestream_to_ipv4(&packet->payload[12], packet->payload_packet_len, &bytes_read);
	
	// and now test the firt 5 bytes of the payload for zattoo pattern
	if(ip == packet->iph->daddr
	   && packet->empty_line_position_set != 0
	   && ((packet->payload_packet_len - packet->empty_line_position) > 10)
	   && packet->payload[packet->empty_line_position + 2] ==
	   0x03
	   && packet->payload[packet->empty_line_position + 3] ==
	   0x04
	   && packet->payload[packet->empty_line_position + 4] ==
	   0x00
	   && packet->payload[packet->empty_line_position + 5] ==
	   0x04
	   && packet->payload[packet->empty_line_position + 6] ==
	   0x0a && packet->payload[packet->empty_line_position + 7] == 0x00) {
	  
	  NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "add connection over tcp with pattern POST http://\n");
	  
	  if(src != NULL)
	    src->zattoo_ts = packet->tick_timestamp;
	  if(dst != NULL)
	    dst->zattoo_ts = packet->tick_timestamp;
	  
	  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_UNKNOWN);
	  return;
	}
      }
    } else if(flow->zattoo_stage == 0) {

      if(packet->payload_packet_len > 50
	 && packet->payload[0] == 0x03
	 && packet->payload[1] == 0x04
	 && packet->payload[2] == 0x00
	 && packet->payload[3] == 0x04 && packet->payload[4] == 0x0a && packet->payload[5] == 0x00) {
	flow->zattoo_stage = 1 + packet->packet_direction;
	NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "need next packet, seen pattern 0x030400040a00\n");
	return;
      }
      /* the following is searching for flash, not for zattoo. */
    } else if(flow->zattoo_stage == 2 - packet->packet_direction && packet->payload_packet_len > 50 && packet->payload[0] == 0x03 && packet->payload[1] == 0x04) {
      
      NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "add connection over tcp with 0x0304.\n");

      if(src != NULL)
	src->zattoo_ts = packet->tick_timestamp;
      if(dst != NULL)
	dst->zattoo_ts = packet->tick_timestamp;
      
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_UNKNOWN);
      return;
      
    } else if(flow->zattoo_stage == 1 + packet->packet_direction) {
      if(packet->payload_packet_len > 500 && packet->payload[0] == 0x00 && packet->payload[1] == 0x00) {
	
	flow->zattoo_stage = 3 + packet->packet_direction;

	NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "need next packet, seen pattern 0x0000\n");
	return;
      }
      if(packet->payload_packet_len > 50
	  && packet->payload[0] == 0x03
	  && packet->payload[1] == 0x04
	  && packet->payload[2] == 0x00
	  && packet->payload[3] == 0x04 && packet->payload[4] == 0x0a && packet->payload[5] == 0x00) {
      }
      NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "need next packet, seen pattern 0x030400040a00\n");
      return;
      
    } else if(flow->zattoo_stage == 4 - packet->packet_direction && packet->payload_packet_len > 50 && packet->payload[0] == 0x03 && packet->payload[1] == 0x04) {

      NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "add connection over tcp with 0x0304.\n");
      
      if(src != NULL)
	src->zattoo_ts = packet->tick_timestamp;
      if(dst != NULL)
	dst->zattoo_ts = packet->tick_timestamp;
      
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_UNKNOWN);
      return;
      
    } else if(flow->zattoo_stage == 5 + packet->packet_direction && (packet->payload_packet_len == 125)) {

      NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "detected zattoo.\n");

      if(src != NULL)
	src->zattoo_ts = packet->tick_timestamp;
      if(dst != NULL)
	dst->zattoo_ts = packet->tick_timestamp;
      
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_UNKNOWN);
      return;
      
    } else if(flow->zattoo_stage == 6 - packet->packet_direction && packet->payload_packet_len == 1412) {
      NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "found zattoo.\n");

      if(src != NULL)
	src->zattoo_ts = packet->tick_timestamp;
      if(dst != NULL)
	dst->zattoo_ts = packet->tick_timestamp;
      
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
    
    NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG,
	     "ZATTOO: discarded the flow (TCP): packet_size: %u; Flowstage: %u\n",
	     packet->payload_packet_len, flow->zattoo_stage);

  }
  /* search over UDP */
  else if(packet->udp != NULL) {

    if(packet->payload_packet_len > 20 && (packet->udp->dest == htons(5003) || packet->udp->source == htons(5003))
       && (get_u_int16_t(packet->payload, 0) == htons(0x037a)
	   || get_u_int16_t(packet->payload, 0) == htons(0x0378)
	   || get_u_int16_t(packet->payload, 0) == htons(0x0305)
	   || get_u_int32_t(packet->payload, 0) == htonl(0x03040004)
	   || get_u_int32_t(packet->payload, 0) == htonl(0x03010005))) {
      
      if(++flow->zattoo_stage == 2) {

	NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "add connection over udp.\n");
	if(src != NULL)
	  src->zattoo_ts = packet->tick_timestamp;
	if(dst != NULL)
	  dst->zattoo_ts = packet->tick_timestamp;
	
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
      NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "need next packet udp.\n");
      return;
    }

    NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG,
	     "ZATTOO: discarded the flow (UDP): packet_size: %u; Flowstage: %u\n",
	     packet->payload_packet_len, flow->zattoo_stage);

  }
  /* exclude ZATTOO */
  NDPI_LOG(NDPI_PROTOCOL_ZATTOO, ndpi_struct, NDPI_LOG_DEBUG, "exclude zattoo.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_ZATTOO);
}


void init_zattoo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Zattoo", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_ZATTOO,
				      ndpi_search_zattoo,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
