/*
 * irc.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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

#ifdef NDPI_PROTOCOL_IRC
#define NDPI_IRC_FIND_LESS(time_err,less) {int t1 = 0;	\
    u_int32_t timestamp = time_err[0];			\
    for(t1=0;t1 < NDPI_PROTOCOL_IRC_MAXPORT;t1++) {	\
      if(timestamp > time_err[t1]) {			\
	timestamp = time_err[t1];			\
	less = t1;}}}

static void ndpi_int_irc_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_IRC, NDPI_PROTOCOL_UNKNOWN);
}

	
#if !defined(WIN32)
static inline
#else
__forceinline static
#endif
u_int8_t ndpi_is_duplicate(struct ndpi_id_struct *id_t, u_int16_t port)
{
  int index = 0;
  while (index < id_t->irc_number_of_port) {
    if (port == id_t->irc_port[index])
      return 1;
    index++;
  }
  return 0;
}

static u_int8_t ndpi_check_for_NOTICE_or_PRIVMSG(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

  struct ndpi_packet_struct *packet = &flow->packet;
  //
  u_int16_t i;
  u_int8_t number_of_lines_to_be_searched_for = 0;
  for (i = 0; i < packet->payload_packet_len - 7; i++) {
    if (packet->payload[i] == 'N' || packet->payload[i] == 'P') {
      if (memcmp(&packet->payload[i + 1], "OTICE ", 6) == 0 || memcmp(&packet->payload[i + 1], "RIVMSG ", 7) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "found NOTICE or PRIVMSG\n");
	return 1;
      }
    }
    if (packet->payload[i] == 0x0a) {
      number_of_lines_to_be_searched_for++;
      if (number_of_lines_to_be_searched_for == 2) {
	return 0;
      }
    }
  }
  return 0;

}

static u_int8_t ndpi_check_for_Nickname(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t i, packetl = packet->payload_packet_len;

  if (packetl < 4) {
    return 0;
  }

  for (i = 0; i < (packetl - 4); i++) {
    if (packet->payload[i] == 'N' || packet->payload[i] == 'n') {
      if ((((packetl - (i + 1)) >= 4) && memcmp(&packet->payload[i + 1], "ick=", 4) == 0)
	  || (((packetl - (i + 1)) >= 8) && (memcmp(&packet->payload[i + 1], "ickname=", 8) == 0))
	  || (((packetl - (i + 1)) >= 8) && (memcmp(&packet->payload[i + 1], "ickName=", 8) == 0))) {
	NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "found HTTP IRC Nickname pattern\n");
	return 1;
      }
    }
  }
  return 0;
}

static u_int8_t ndpi_check_for_cmd(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t i;

  if (packet->payload_packet_len < 4) {
    return 0;
  }

  for (i = 0; i < packet->payload_packet_len - 4; i++) {
    if (packet->payload[i] == 'c') {
      if (memcmp(&packet->payload[i + 1], "md=", 3) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "found HTTP IRC cmd pattern  \n");
	return 1;
      }
    }
  }
  return 0;
}

static u_int8_t ndpi_check_for_IRC_traces(const u_int8_t * ptr, u_int16_t len)
{
  u_int16_t i;

  if (len < 4) {
    return 0;
  }

  for (i = 0; i < len - 4; i++) {
    if (ptr[i] == 'i') {
      if (memcmp(&ptr[i + 1], "rc.", 3) == 0) {
	return 1;
      }
    }
  }
  return 0;
}


u_int8_t ndpi_search_irc_ssl_detect_ninety_percent_but_very_fast(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

  struct ndpi_packet_struct *packet = &flow->packet;
	

  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG,
	   "called ndpi_search_irc_ssl_detect_ninety_percent_but_very_fast\n");

  /* case 1: len 1460, len 1460, len 1176 several times in one direction, than len = 4, 4096, 8192 in the other direction */
  if (packet->payload_packet_len == 1460
      && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0) || (flow->l4.tcp.irc_stage2 == 3
										&& flow->l4.tcp.irc_direction ==
										1 + packet->packet_direction))) {
    flow->l4.tcp.irc_stage2 = 1;
    flow->l4.tcp.irc_direction = 1 + packet->packet_direction;
    return 1;
  }
  if (packet->payload_packet_len == 1460 && flow->l4.tcp.irc_stage2 == 1
      && flow->l4.tcp.irc_direction == 1 + packet->packet_direction) {
    flow->l4.tcp.irc_stage2 = 2;
    return 1;
  }
  if (packet->payload_packet_len == 1176 && flow->l4.tcp.irc_stage2 == 2
      && flow->l4.tcp.irc_direction == 1 + packet->packet_direction) {
    flow->l4.tcp.irc_stage2 = 3;
    flow->l4.tcp.irc_0x1000_full = 1;
    return 1;
  }
  if (packet->payload_packet_len == 4 && (flow->l4.tcp.irc_stage2 == 3 || flow->l4.tcp.irc_0x1000_full == 1)
      && flow->l4.tcp.irc_direction == 2 - packet->packet_direction && (ntohs(get_u_int16_t(packet->payload, 2)) == 0x1000
									|| ntohs(get_u_int16_t(packet->payload, 2)) ==
									0x2000)) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "IRC SSL detected: ->1460,1460,1176,<-4096||8192");
    ndpi_int_irc_add_connection(ndpi_struct, flow);
    return 1;
  }
  /* case 2: len 1448, len 1448, len 1200 several times in one direction, than len = 4, 4096, 8192 in the other direction */
  if (packet->payload_packet_len == 1448
      && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0) || (flow->l4.tcp.irc_stage2 == 6
										&& flow->l4.tcp.irc_direction ==
										1 + packet->packet_direction))) {
    flow->l4.tcp.irc_stage2 = 4;
    flow->l4.tcp.irc_direction = 1 + packet->packet_direction;
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "len = 1448 first\n");
    return 1;
  }
  if (packet->payload_packet_len == 1448 && flow->l4.tcp.irc_stage2 == 4
      && flow->l4.tcp.irc_direction == 1 + packet->packet_direction) {
    flow->l4.tcp.irc_stage2 = 5;
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "len = 1448 second \n");
    return 1;
  }
  if (packet->payload_packet_len == 1200 && flow->l4.tcp.irc_stage2 == 5
      && flow->l4.tcp.irc_direction == 1 + packet->packet_direction) {
    flow->l4.tcp.irc_stage2 = 6;
    flow->l4.tcp.irc_0x1000_full = 1;
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "len = 1200  \n");
    return 1;
  }
  if (packet->payload_packet_len == 4 && (flow->l4.tcp.irc_stage2 == 6 || flow->l4.tcp.irc_0x1000_full == 1)
      && flow->l4.tcp.irc_direction == 2 - packet->packet_direction && (ntohs(get_u_int16_t(packet->payload, 2)) == 0x1000
									|| ntohs(get_u_int16_t(packet->payload, 2)) ==
									0x2000)) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "IRC SSL detected: ->1448,1448,1200,<-4096||8192");
    ndpi_int_irc_add_connection(ndpi_struct, flow);
    return 1;
  }
  /* case 3: several packets with len 1380, 1200, 1024, 1448, 1248,
   * than one packet in the other direction with the len or two times the len. */
  if (packet->payload_packet_len == 1380 && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0)
					     || (flow->l4.tcp.irc_stage2 == 7
						 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction))) {
    flow->l4.tcp.irc_stage2 = 7;
    flow->l4.tcp.irc_direction = 1 + packet->packet_direction;
    return 1;
  }
  if (packet->payload_packet_len == 4 && flow->l4.tcp.irc_stage2 == 7
      && flow->l4.tcp.irc_direction == 2 - packet->packet_direction && (ntohs(get_u_int16_t(packet->payload, 2)) == 1380
									|| ntohs(get_u_int16_t(packet->payload, 2)) ==
									2760)) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "IRC SSL detected: ->1380,<-1380||2760");
    ndpi_int_irc_add_connection(ndpi_struct, flow);
    return 1;
  }
  if (packet->payload_packet_len == 1200 && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0)
					     || (flow->l4.tcp.irc_stage2 == 8
						 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction))) {
    flow->l4.tcp.irc_stage2 = 8;
    flow->l4.tcp.irc_direction = 1 + packet->packet_direction;
    return 1;
  }
  if (packet->payload_packet_len == 4 && flow->l4.tcp.irc_stage2 == 8
      && flow->l4.tcp.irc_direction == 2 - packet->packet_direction && (ntohs(get_u_int16_t(packet->payload, 2)) == 1200
									|| ntohs(get_u_int16_t(packet->payload, 2)) ==
									2400)) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "IRC SSL detected: ->1200,<-1200||2400");
    ndpi_int_irc_add_connection(ndpi_struct, flow);
    return 1;
  }
  if (packet->payload_packet_len == 1024 && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0)
					     || (flow->l4.tcp.irc_stage2 == 9
						 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction))) {
    flow->l4.tcp.irc_stage2 = 9;
    flow->l4.tcp.irc_direction = 1 + packet->packet_direction;
    return 1;
  }
  if (packet->payload_packet_len == 4 && (flow->l4.tcp.irc_stage2 == 9 || flow->l4.tcp.irc_stage2 == 15)
      && flow->l4.tcp.irc_direction == 2 - packet->packet_direction && (ntohs(get_u_int16_t(packet->payload, 2)) == 1024
									|| ntohs(get_u_int16_t(packet->payload, 2)) ==
									2048)) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "IRC SSL detected: ->1024,<-1024||2048");
    ndpi_int_irc_add_connection(ndpi_struct, flow);
    return 1;
  }
  if (packet->payload_packet_len == 1248 && ((flow->l4.tcp.irc_stage2 == 0 && flow->l4.tcp.irc_direction == 0)
					     || (flow->l4.tcp.irc_stage2 == 10
						 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction))) {
    flow->l4.tcp.irc_stage2 = 10;
    flow->l4.tcp.irc_direction = 1 + packet->packet_direction;
    return 1;
  }
  if (packet->payload_packet_len == 4 && flow->l4.tcp.irc_stage2 == 10
      && flow->l4.tcp.irc_direction == 2 - packet->packet_direction && (ntohs(get_u_int16_t(packet->payload, 2)) == 1248
									|| ntohs(get_u_int16_t(packet->payload, 2)) ==
									2496)) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "IRC SSL detected: ->1248,<-1248||2496");
    ndpi_int_irc_add_connection(ndpi_struct, flow);
    return 1;
  }
  if (packet->payload_packet_len == 1448
      && (flow->l4.tcp.irc_stage2 == 5 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction)) {
    flow->l4.tcp.irc_stage2 = 11;
    return 1;
  }
  if (packet->payload_packet_len == 4
      && (flow->l4.tcp.irc_stage2 == 4 || flow->l4.tcp.irc_stage2 == 5 || flow->l4.tcp.irc_stage2 == 11
	  || flow->l4.tcp.irc_stage2 == 13)
      && flow->l4.tcp.irc_direction == 2 - packet->packet_direction && (ntohs(get_u_int16_t(packet->payload, 2)) == 1448
									|| ntohs(get_u_int16_t(packet->payload, 2)) ==
									2896)) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "IRC SSL detected: ->1448,<-1448||2896");
    ndpi_int_irc_add_connection(ndpi_struct, flow);
    return 1;
  }
  /* case 4 : five packets with len = 1448, one with len 952, than one packet from other direction len = 8192 */
  if (packet->payload_packet_len == 1448
      && (flow->l4.tcp.irc_stage2 == 11 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction)) {
    flow->l4.tcp.irc_stage2 = 12;
    return 1;
  }
  if (packet->payload_packet_len == 1448
      && (flow->l4.tcp.irc_stage2 == 12 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction)) {
    flow->l4.tcp.irc_stage2 = 13;
    return 1;
  }
  if (packet->payload_packet_len == 952
      && (flow->l4.tcp.irc_stage2 == 13 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction)) {
    flow->l4.tcp.irc_stage2 = 14;
    return 1;
  }
  if (packet->payload_packet_len == 4
      && flow->l4.tcp.irc_stage2 == 14
      && flow->l4.tcp.irc_direction == 2 - packet->packet_direction && ntohs(get_u_int16_t(packet->payload, 2)) == 8192) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
	     "IRC SSL detected: ->1448,1448,1448,1448,1448,952,<-8192");
    ndpi_int_irc_add_connection(ndpi_struct, flow);
    return 1;
  }
  /* case 5: len 1024, len 1448, len 1448, len 1200, len 1448, len 600 */
  if (packet->payload_packet_len == 1448
      && (flow->l4.tcp.irc_stage2 == 9 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction)) {
    flow->l4.tcp.irc_stage2 = 15;
    return 1;
  }
  if (packet->payload_packet_len == 1448
      && (flow->l4.tcp.irc_stage2 == 15 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction)) {
    flow->l4.tcp.irc_stage2 = 16;
    return 1;
  }
  if (packet->payload_packet_len == 1200
      && (flow->l4.tcp.irc_stage2 == 16 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction)) {
    flow->l4.tcp.irc_stage2 = 17;
    return 1;
  }
  if (packet->payload_packet_len == 1448
      && (flow->l4.tcp.irc_stage2 == 17 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction)) {
    flow->l4.tcp.irc_stage2 = 18;
    return 1;
  }
  if (packet->payload_packet_len == 600
      && (flow->l4.tcp.irc_stage2 == 18 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction)) {
    flow->l4.tcp.irc_stage2 = 19;
    return 1;
  }
  if (packet->payload_packet_len == 4
      && flow->l4.tcp.irc_stage2 == 19
      && flow->l4.tcp.irc_direction == 2 - packet->packet_direction && ntohs(get_u_int16_t(packet->payload, 2)) == 7168) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
	     "IRC SSL detected: ->1024,1448,1448,1200,1448,600,<-7168");
    ndpi_int_irc_add_connection(ndpi_struct, flow);
    return 1;
  }
  /* -> 1024, 1380, -> 2404    */
  if (packet->payload_packet_len == 1380
      && (flow->l4.tcp.irc_stage2 == 9 && flow->l4.tcp.irc_direction == 1 + packet->packet_direction)) {
    flow->l4.tcp.irc_stage2 = 20;
    return 1;
  }
  if (packet->payload_packet_len == 4
      && flow->l4.tcp.irc_stage2 == 20
      && flow->l4.tcp.irc_direction == 2 - packet->packet_direction && ntohs(get_u_int16_t(packet->payload, 2)) == 2404) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "IRC SSL detected: ->1024,1380 <-2404");
    ndpi_int_irc_add_connection(ndpi_struct, flow);
    return 1;

  }
  return 0;
}


void ndpi_search_irc_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;
  int less;
  u_int16_t c = 0;
  u_int16_t c1 = 0;
  u_int16_t port = 0;
  u_int16_t sport = 0;
  u_int16_t dport = 0;
  u_int16_t counter = 0;
  u_int16_t i = 0;
  u_int16_t j = 0;
  u_int16_t k = 0;
  u_int16_t h;
  u_int16_t http_content_ptr_len = 0;
  u_int8_t space = 0;

  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "irc : search irc\n");
  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_IRC && flow->packet_counter > 70) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "exclude irc, packet_counter > 70\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_IRC);
    return;
  }
  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_IRC && flow->packet_counter > 30 &&
      flow->l4.tcp.irc_stage2 == 0) {
    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "packet_counter > 30, exclude irc.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_IRC);
    return;
  }
  if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_IRC) {
    if (src != NULL && ((u_int32_t)
			(packet->tick_timestamp - src->irc_ts) < ndpi_struct->irc_timeout)) {
      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "irc : save src connection packet detected\n");
      src->irc_ts = packet->tick_timestamp;
    } else if (dst != NULL && ((u_int32_t)
			       (packet->tick_timestamp - dst->irc_ts) < ndpi_struct->irc_timeout)) {
      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "irc : save dst connection packet detected\n");
      dst->irc_ts = packet->tick_timestamp;
    }
  }

  if (((dst != NULL && NDPI_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, NDPI_PROTOCOL_IRC)
	&& ((u_int32_t)
	    (packet->tick_timestamp - dst->irc_ts)) <
	ndpi_struct->irc_timeout)) || (src != NULL
				       &&
				       NDPI_COMPARE_PROTOCOL_TO_BITMASK
				       (src->detected_protocol_bitmask, NDPI_PROTOCOL_IRC)
				       && ((u_int32_t)
					   (packet->tick_timestamp - src->irc_ts)) < ndpi_struct->irc_timeout)) {
    if (packet->tcp != NULL) {
      sport = packet->tcp->source;
      dport = packet->tcp->dest;
    }
    if (dst != NULL) {
      for (counter = 0; counter < dst->irc_number_of_port; counter++) {
	if (dst->irc_port[counter] == sport || dst->irc_port[counter] == dport) {
	  dst->last_time_port_used[counter] = packet->tick_timestamp;
	  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
		   "dest port matched with the DCC port and the flow is marked as IRC");
	  ndpi_int_irc_add_connection(ndpi_struct, flow);
	  return;
	}
      }
    }
    if (src != NULL) {
      for (counter = 0; counter < src->irc_number_of_port; counter++) {
	if (src->irc_port[counter] == sport || src->irc_port[counter] == dport) {
	  src->last_time_port_used[counter] = packet->tick_timestamp;
	  ndpi_int_irc_add_connection(ndpi_struct, flow);
	  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
		   "Source port matched with the DCC port and the flow is marked as IRC");
	  return;
	}
      }
    }
  }



  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_IRC
      && flow->packet_counter == 2 && (packet->payload_packet_len > 400 && packet->payload_packet_len < 1381)) {
    for (c1 = 50; c1 < packet->payload_packet_len - 23; c1++) {
      if (packet->payload[c1] == 'i' || packet->payload[c1] == 'd') {
	if ((memcmp(&packet->payload[c1], "irc.hackthissite.org0", 21)
	     == 0)
	    || (memcmp(&packet->payload[c1], "irc.gamepad.ca1", 15) == 0)
	    || (memcmp(&packet->payload[c1], "dungeon.axenet.org0", 19)
		== 0)
	    || (memcmp(&packet->payload[c1], "dazed.nuggethaus.net", 20)
		== 0)
	    || (memcmp(&packet->payload[c1], "irc.indymedia.org", 17)
		== 0)
	    || (memcmp(&packet->payload[c1], "irc.cccp-project.net", 20)
		== 0)
	    || (memcmp(&packet->payload[c1], "dirc.followell.net0", 19)
		== 0)
	    || (memcmp(&packet->payload[c1], "irc.discostars.de1", 18)
		== 0)
	    || (memcmp(&packet->payload[c1], "irc.rizon.net", 13) == 0)) {
	  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
		   "IRC SSL detected with :- irc.hackthissite.org0 | irc.gamepad.ca1 | dungeon.axenet.org0 "
		   "| dazed.nuggethaus.net | irc.indymedia.org | irc.discostars.de1 ");
	  ndpi_int_irc_add_connection(ndpi_struct, flow);
	  break;
	}
      }
    }
  }
  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_IRC &&
      ndpi_search_irc_ssl_detect_ninety_percent_but_very_fast(ndpi_struct, flow) != 0) {
    return;
  }

  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_IRC && flow->packet_counter < 20
      && packet->payload_packet_len >= 8) {
    if (get_u_int8_t(packet->payload, packet->payload_packet_len - 1) == 0x0a
	|| (ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0a00)) {
      if (memcmp(packet->payload, ":", 1) == 0) {
	if (packet->payload[packet->payload_packet_len - 2] != 0x0d
	    && packet->payload[packet->payload_packet_len - 1] == 0x0a) {
	  ndpi_parse_packet_line_info_any(ndpi_struct, flow);
	} else if (packet->payload[packet->payload_packet_len - 2] == 0x0d) {
	  ndpi_parse_packet_line_info(ndpi_struct, flow);
	} else {
	  flow->l4.tcp.irc_3a_counter++;
	}
	for (i = 0; i < packet->parsed_lines; i++) {
	  if (packet->line[i].ptr[0] == ':') {
	    flow->l4.tcp.irc_3a_counter++;
	    if (flow->l4.tcp.irc_3a_counter == 7) {	/* ':' == 0x3a */
	      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "0x3a. seven times. found irc.");
	      ndpi_int_irc_add_connection(ndpi_struct, flow);
	      goto detected_irc;
	    }
	  }
	}
	if (flow->l4.tcp.irc_3a_counter == 7) {	/* ':' == 0x3a */
	  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "0x3a. seven times. found irc.");
	  ndpi_int_irc_add_connection(ndpi_struct, flow);
	  goto detected_irc;
	}
      }
      if ((memcmp(packet->payload, "USER ", 5) == 0)
	  || (memcmp(packet->payload, "NICK ", 5) == 0)
	  || (memcmp(packet->payload, "PASS ", 5) == 0)
	  || (memcmp(packet->payload, ":", 1) == 0 && ndpi_check_for_NOTICE_or_PRIVMSG(ndpi_struct, flow) != 0)
	  || (memcmp(packet->payload, "PONG ", 5) == 0)
	  || (memcmp(packet->payload, "PING ", 5) == 0)
	  || (memcmp(packet->payload, "JOIN ", 5) == 0)
	  || (memcmp(packet->payload, "NOTICE ", 7) == 0)
	  || (memcmp(packet->payload, "PRIVMSG ", 8) == 0)
	  || (memcmp(packet->payload, "VERSION ", 8) == 0)) {
	NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
		 "USER, NICK, PASS, NOTICE, PRIVMSG one time");
	if (flow->l4.tcp.irc_stage == 2) {
	  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "found irc");
	  ndpi_int_irc_add_connection(ndpi_struct, flow);
	  flow->l4.tcp.irc_stage = 3;
	}
	if (flow->l4.tcp.irc_stage == 1) {
	  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "second time, stage=2");
	  flow->l4.tcp.irc_stage = 2;
	}
	if (flow->l4.tcp.irc_stage == 0) {
	  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "first time, stage=1");
	  flow->l4.tcp.irc_stage = 1;
	}
	/* irc packets can have either windows line breaks (0d0a) or unix line breaks (0a) */
	if (packet->payload[packet->payload_packet_len - 2] == 0x0d
	    && packet->payload[packet->payload_packet_len - 1] == 0x0a) {
	  ndpi_parse_packet_line_info(ndpi_struct, flow);
	  if (packet->parsed_lines > 1) {
	    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
		     "packet contains more than one line");
	    for (c = 1; c < packet->parsed_lines; c++) {
	      if (packet->line[c].len > 4 && (memcmp(packet->line[c].ptr, "NICK ", 5) == 0
					      || memcmp(packet->line[c].ptr, "USER ", 5) == 0)) {
		NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct,
			 NDPI_LOG_TRACE, "two icq signal words in the same packet");
		ndpi_int_irc_add_connection(ndpi_struct, flow);
		flow->l4.tcp.irc_stage = 3;
		return;
	      }
	    }
	  }

	} else if (packet->payload[packet->payload_packet_len - 1] == 0x0a) {
	  ndpi_parse_packet_line_info_any(ndpi_struct, flow);
	  if (packet->parsed_lines > 1) {
	    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
		     "packet contains more than one line");
	    for (c = 1; c < packet->parsed_lines; c++) {
	      if (packet->line[c].len > 4 && (memcmp(packet->line[c].ptr, "NICK ", 5) == 0
						   || memcmp(packet->line[c].ptr, "USER ",
							     5) == 0)) {
		NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
			 "two icq signal words in the same packet");
		ndpi_int_irc_add_connection(ndpi_struct, flow);
		flow->l4.tcp.irc_stage = 3;
		return;
	      }
	    }
	  }
	}
      }
    }
  }

  /**
   * Trying to primarily detect the HTTP Web based IRC chat patterns based on the HTTP headers
   * during the User login time.When the HTTP data gets posted using the POST method ,patterns
   * will be searched in the HTTP content.
   */
  if ((flow->detected_protocol_stack[0] != NDPI_PROTOCOL_IRC) && (flow->l4.tcp.irc_stage == 0)
      && (packet->payload_packet_len > 5)) {
    //HTTP POST Method being employed
    if (memcmp(packet->payload, "POST ", 5) == 0) {
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      if (packet->parsed_lines) {
		  u_int16_t http_header_len = (u_int16_t)((packet->line[packet->parsed_lines - 1].ptr - packet->payload) + 2);
	if (packet->payload_packet_len > http_header_len) {
	  http_content_ptr_len = packet->payload_packet_len - http_header_len;
	}
	if ((ndpi_check_for_IRC_traces(packet->line[0].ptr, packet->line[0].len))
	    || ((packet->http_url_name.ptr)
		&& (ndpi_check_for_IRC_traces(packet->http_url_name.ptr, packet->http_url_name.len)))
	    || ((packet->referer_line.ptr)
		&& (ndpi_check_for_IRC_traces(packet->referer_line.ptr, packet->referer_line.len)))) {
	  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
		   "IRC detected from the Http URL/ Referer header ");
	  flow->l4.tcp.irc_stage = 1;
	  // HTTP POST Request body is not in the same packet.
	  if (!http_content_ptr_len) {
	    return;
	  }
	}
      }
    }
  }

  if ((flow->detected_protocol_stack[0] != NDPI_PROTOCOL_IRC) && (flow->l4.tcp.irc_stage == 1)) {
    if ((((packet->payload_packet_len - http_content_ptr_len) > 10)
	 && (memcmp(packet->payload + http_content_ptr_len, "interface=", 10) == 0)
	 && (ndpi_check_for_Nickname(ndpi_struct, flow) != 0))
	|| (((packet->payload_packet_len - http_content_ptr_len) > 5)
	    && (memcmp(packet->payload + http_content_ptr_len, "item=", 5) == 0)
	    && (ndpi_check_for_cmd(ndpi_struct, flow) != 0))) {
      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "IRC Nickname, cmd,  one time");
      ndpi_int_irc_add_connection(ndpi_struct, flow);
      return;
    }
  }

 detected_irc:
  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "detected_irc:");

  if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_IRC) {
    /* maybe this can be deleted at the end */

    if (packet->payload[packet->payload_packet_len - 2] != 0x0d
	&& packet->payload[packet->payload_packet_len - 1] == 0x0a) {
      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG,
	       "ndpi_parse_packet_line_info_any(ndpi_struct, flow);");
      ndpi_parse_packet_line_info_any(ndpi_struct, flow);
    } else if (packet->payload[packet->payload_packet_len - 2] == 0x0d) {
      ndpi_parse_packet_line_info(ndpi_struct, flow);
    } else {
      return;
    }
    for (i = 0; i < packet->parsed_lines; i++) {
      if (packet->line[i].len > 6 && memcmp(packet->line[i].ptr, "NOTICE ", 7) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "NOTICE");
	for (j = 7; j < packet->line[i].len - 8; j++) {
	  if (packet->line[i].ptr[j] == ':') {
	    if (memcmp(&packet->line[i].ptr[j + 1], "DCC SEND ", 9) == 0
		|| memcmp(&packet->line[i].ptr[j + 1], "DCC CHAT ", 9) == 0) {
	      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
		       "found NOTICE and DCC CHAT or DCC SEND.");
	    }
	  }
	}
      }
      if (packet->payload_packet_len > 0 && packet->payload[0] == 0x3a /* 0x3a = ':' */ ) {
	NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "3a");
	for (j = 1; j < packet->line[i].len - 9; j++) {
	  if (packet->line[i].ptr[j] == ' ') {
	    j++;
	    if (packet->line[i].ptr[j] == 'P') {
	      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "P");
	      j++;
	      if (memcmp(&packet->line[i].ptr[j], "RIVMSG ", 7) == 0)
		NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "RIVMSG");
	      h = j + 7;
	      goto read_privmsg;
	    }
	  }
	}
      }
      if (packet->line[i].len > 7 && (memcmp(packet->line[i].ptr, "PRIVMSG ", 8) == 0)) {
	NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG, "PRIVMSG	");
	h = 7;
      read_privmsg:
	for (j = h; j < packet->line[i].len - 9; j++) {
	  if (packet->line[i].ptr[j] == ':') {
	    if (memcmp(&packet->line[i].ptr[j + 1], "xdcc ", 5) == 0) {
	      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "xdcc should match.");
	    }
	    j += 2;
	    if (memcmp(&packet->line[i].ptr[j], "DCC ", 4) == 0) {
	      j += 4;
	      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "found DCC.");
	      if (memcmp(&packet->line[i].ptr[j], "SEND ", 5) == 0
		  || (memcmp(&packet->line[i].ptr[j], "CHAT", 4) == 0)
		  || (memcmp(&packet->line[i].ptr[j], "chat", 4) == 0)
		  || (memcmp(&packet->line[i].ptr[j], "sslchat", 7) == 0)
		  || (memcmp(&packet->line[i].ptr[j], "TSEND", 5) == 0)) {
		NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
			 "found CHAT,chat,sslchat,TSEND.");
		j += 4;

		while (packet->line[i].len > j &&
		       ((packet->line[i].ptr[j] >= 'a' && packet->line[i].ptr[j] <= 'z')
			|| (packet->line[i].ptr[j] >= 'A' && packet->line[i].ptr[j] <= 'Z')
			|| (packet->line[i].ptr[j] >= '0' && packet->line[i].ptr[j] <= '9')
			|| (packet->line[i].ptr[j] >= ' ')
			|| (packet->line[i].ptr[j] >= '.')
			|| (packet->line[i].ptr[j] >= '-'))) {

		  if (packet->line[i].ptr[j] == ' ') {
		    space++;
		    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "space %u.", space);
		  }
		  if (space == 3) {
		    j++;
		    NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "read port.");
		    if (src != NULL) {
		      k = j;
		      port =
			ntohs_ndpi_bytestream_to_number
			(&packet->line[i].ptr[j], packet->payload_packet_len - j, &j);
		      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "port %u.",
			       port);
		      j = k;
		      // hier jetzt überlegen, wie die ports abgespeichert werden sollen
		      if (src->irc_number_of_port < NDPI_PROTOCOL_IRC_MAXPORT)
			NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE,
				 "src->irc_number_of_port < NDPI_PROTOCOL_IRC_MAXPORT.");
		      if (src->irc_number_of_port < NDPI_PROTOCOL_IRC_MAXPORT && port != 0) {
			if (!ndpi_is_duplicate(src, port)) {
			  src->irc_port[src->irc_number_of_port]
			    = port;
			  src->irc_number_of_port++;
			  NDPI_LOG
			    (NDPI_PROTOCOL_IRC,
			     ndpi_struct,
			     NDPI_LOG_DEBUG, "found port=%d",
			     ntohs(get_u_int16_t(src->irc_port, 0)));
			  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG,
				   "jjeeeeeeeeeeeeeeeeeeeeeeeee");
			}
			src->irc_ts = packet->tick_timestamp;
		      } else if (port != 0 && src->irc_number_of_port == NDPI_PROTOCOL_IRC_MAXPORT) {
			if (!ndpi_is_duplicate(src, port)) {
			  less = 0;
			  NDPI_IRC_FIND_LESS(src->last_time_port_used, less);
			  src->irc_port[less] = port;
			  NDPI_LOG
			    (NDPI_PROTOCOL_IRC,
			     ndpi_struct,
			     NDPI_LOG_DEBUG, "found port=%d",
			     ntohs(get_u_int16_t(src->irc_port, 0)));
			}
			src->irc_ts = packet->tick_timestamp;
		      }
		      if (dst == NULL) {
			break;
		      }
		    }
		    if (dst != NULL) {
		      port = ntohs_ndpi_bytestream_to_number
			(&packet->line[i].ptr[j], packet->payload_packet_len - j, &j);
		      NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_TRACE, "port %u.",
			       port);
		      // hier das gleiche wie oben.
		      /* hier werden NDPI_PROTOCOL_IRC_MAXPORT ports pro irc flows mitgespeichert. könnte man denn nicht ein-
		       * fach an die dst oder src einen flag setzten, dass dieser port für eine bestimmte
		       * zeit ein irc-port bleibt?
		       */
		      if (dst->irc_number_of_port < NDPI_PROTOCOL_IRC_MAXPORT && port != 0) {
			if (!ndpi_is_duplicate(dst, port)) {
			  dst->irc_port[dst->irc_number_of_port]
			    = port;
			  dst->irc_number_of_port++;
			  NDPI_LOG
			    (NDPI_PROTOCOL_IRC,
			     ndpi_struct,
			     NDPI_LOG_DEBUG, "found port=%d",
			     ntohs(get_u_int16_t(dst->irc_port, 0)));
			  NDPI_LOG(NDPI_PROTOCOL_IRC, ndpi_struct, NDPI_LOG_DEBUG,
				   "juuuuuuuuuuuuuuuu");
			}
			dst->irc_ts = packet->tick_timestamp;
		      } else if (port != 0 && dst->irc_number_of_port == NDPI_PROTOCOL_IRC_MAXPORT) {
			if (!ndpi_is_duplicate(dst, port)) {
			  less = 0;
			  NDPI_IRC_FIND_LESS(dst->last_time_port_used, less);
			  dst->irc_port[less] = port;

			  NDPI_LOG
			    (NDPI_PROTOCOL_IRC,
			     ndpi_struct,
			     NDPI_LOG_DEBUG, "found port=%d",
			     ntohs(get_u_int16_t(dst->irc_port, 0)));
			}
			dst->irc_ts = packet->tick_timestamp;
		      }

		      break;
		    }
		  }


		  j++;
		}

	      }
	    }
	  }
	}

      }
    }
  }
}


void init_irc_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("IRC", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IRC,
				      ndpi_search_irc_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
