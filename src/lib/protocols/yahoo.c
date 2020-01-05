/*
 * yahoo.c
 *
 * Copyright (C) 2016-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_YAHOO

#include "ndpi_api.h"

struct ndpi_yahoo_header {
  u_int8_t YMSG_str[4];
  u_int16_t version;
  u_int16_t nothing0;
  u_int16_t len;
  u_int16_t service;
  u_int32_t status;
  u_int32_t session_id;
};

/* This function checks the pattern '<Ymsg Command=' in line 8 of parsed lines or
 * in the payload*/
static u_int8_t ndpi_check_for_YmsgCommand(u_int16_t len, const u_int8_t * ptr)
{
  u_int16_t i;

  for (i = 0; i < len - 12; i++) {
    if (ptr[i] == 'Y') {
      if (memcmp(&ptr[i + 1], "msg Command=", 12) == 0) {
	return 1;
      }
    }
  }
  return 0;
}

       
#if !defined(WIN32)
static inline
#elif defined(MINGW_GCC)
__mingw_forceinline static
#else
__forceinline static
#endif
u_int8_t check_ymsg(const u_int8_t * payload, u_int16_t payload_packet_len)
{
  const struct ndpi_yahoo_header *yahoo = (struct ndpi_yahoo_header *) payload;
  
  u_int16_t yahoo_len_parsed = 0;
  do {
    u_int16_t ylen = ntohs(yahoo->len);
    
    yahoo_len_parsed += 20 + ylen;	/* possible overflow here: 20 + ylen = 0x10000 --> 0 --> infinite loop */

    if(ylen >= payload_packet_len || yahoo_len_parsed >= payload_packet_len)
      break;

    yahoo = (struct ndpi_yahoo_header *) (payload + yahoo_len_parsed);
  }
  while(memcmp(yahoo->YMSG_str, "YMSG", 4) == 0);

  if(yahoo_len_parsed == payload_packet_len)
    return 1;
  
  return 0;
}

static void ndpi_search_yahoo_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  const struct ndpi_yahoo_header *yahoo = (struct ndpi_yahoo_header *) packet->payload;

    if(packet->payload_packet_len > 0) {
      /* packet must be at least 20 bytes long */
      if(packet->payload_packet_len >= 20
	 && memcmp(yahoo->YMSG_str, "YMSG", 4) == 0 && ((packet->payload_packet_len - 20) == ntohs(yahoo->len)
							|| check_ymsg(packet->payload, packet->payload_packet_len))) {
     
	NDPI_LOG_DBG(ndpi_struct, "YAHOO FOUND\n");
	flow->yahoo_detection_finished = 2;

	if(ntohs(yahoo->service) == 24 || ntohs(yahoo->service) == 152 || ntohs(yahoo->service) == 74) {
	  NDPI_LOG_DBG(ndpi_struct, "YAHOO conference or chat invite  found");

	  if(src != NULL)
	    src->yahoo_conf_logged_in = 1;
	  if(dst != NULL)
	    dst->yahoo_conf_logged_in = 1;
	}
	if(ntohs(yahoo->service) == 27 || ntohs(yahoo->service) == 155 || ntohs(yahoo->service) == 160) {
	  NDPI_LOG_DBG(ndpi_struct, "YAHOO conference or chat logoff found");
	  if(src != NULL) {
	    src->yahoo_conf_logged_in = 0;
	    src->yahoo_voice_conf_logged_in = 0;
	  }
	}
	NDPI_LOG_INFO(ndpi_struct, "found YAHOO");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	return;
	
      } else if(flow->yahoo_detection_finished == 2 && packet->detected_protocol_stack[0] == NDPI_PROTOCOL_YAHOO) {
	return;
      } else if(packet->payload_packet_len == 4 && memcmp(yahoo->YMSG_str, "YMSG", 4) == 0) {
	flow->l4.tcp.yahoo_sip_comm = 1;
	return;
      } else if(flow->l4.tcp.yahoo_sip_comm && packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN
		&& flow->packet_counter < 3) {
	return;
      }

      /* now test for http login, at least 100 a bytes packet */
      if(ndpi_struct->yahoo_detect_http_connections != 0 && packet->payload_packet_len > 100) {
	if(memcmp(packet->payload, "POST /relay?token=", 18) == 0
	   || memcmp(packet->payload, "GET /relay?token=", 17) == 0
	   || memcmp(packet->payload, "GET /?token=", 12) == 0
	   || memcmp(packet->payload, "HEAD /relay?token=", 18) == 0) {
	  if((src != NULL
	      && NDPI_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, NDPI_PROTOCOL_YAHOO)
	      != 0) || (dst != NULL
			&& NDPI_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, NDPI_PROTOCOL_YAHOO)
			!= 0)) {
	    /* this is mostly a file transfer */
	    NDPI_LOG_INFO(ndpi_struct, "found YAHOO");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	}
	if(memcmp(packet->payload, "POST ", 5) == 0) {
	  u_int16_t a;
	  ndpi_parse_packet_line_info(ndpi_struct, flow);

	  if ((packet->user_agent_line.len >= 21)
	      && (memcmp(packet->user_agent_line.ptr, "YahooMobileMessenger/", 21) == 0)) {
	    NDPI_LOG_INFO(ndpi_struct, "found YAHOO(Mobile)");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	  
	  if (NDPI_SRC_OR_DST_HAS_PROTOCOL(src, dst, NDPI_PROTOCOL_YAHOO)
	      && packet->parsed_lines > 5
	      && memcmp(&packet->payload[5], "/Messenger.", 11) == 0
	      && packet->line[1].len >= 17
	      && memcmp(packet->line[1].ptr, "Connection: Close",
			17) == 0 && packet->line[2].len >= 6
	      && memcmp(packet->line[2].ptr, "Host: ", 6) == 0
	      && packet->line[3].len >= 16
	      && memcmp(packet->line[3].ptr, "Content-Length: ",
			16) == 0 && packet->line[4].len >= 23
	      && memcmp(packet->line[4].ptr, "User-Agent: Mozilla/5.0",
			23) == 0 && packet->line[5].len >= 23
	      && memcmp(packet->line[5].ptr, "Cache-Control: no-cache", 23) == 0) {
	    NDPI_LOG_INFO(ndpi_struct, "found YAHOO HTTP POST P2P FILETRANSFER\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }

	  if (packet->host_line.ptr != NULL && packet->host_line.len >= 26 &&
	      memcmp(packet->host_line.ptr, "filetransfer.msg.yahoo.com", 26) == 0) {
	    NDPI_LOG_INFO(ndpi_struct, "found YAHOO HTTP POST FILETRANSFER\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	  /* now check every line */
	  for (a = 0; a < packet->parsed_lines; a++) {
	    if (packet->line[a].len >= 4 && memcmp(packet->line[a].ptr, "YMSG", 4) == 0) {
	      NDPI_LOG_DBG(ndpi_struct,
		       "YAHOO HTTP POST FOUND, line is: %.*s\n", packet->line[a].len, packet->line[a].ptr);
	      NDPI_LOG_INFO(ndpi_struct, "found YAHOO");
	      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	      return;
	    }
	  }
	  if (packet->parsed_lines > 8 && packet->line[8].len > 250 && packet->line[8].ptr != NULL) {
	    if (memcmp(packet->line[8].ptr, "<Session ", 9) == 0) {
	      if (ndpi_check_for_YmsgCommand(packet->line[8].len, packet->line[8].ptr)) {
		NDPI_LOG_INFO(ndpi_struct,
			 "found YAHOO HTTP Proxy Yahoo Chat <Ymsg Command= pattern  \n");
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
		return;
	      }
	    }
	  }
	}
	if(memcmp(packet->payload, "GET /Messenger.", 15) == 0) {
	  if((src != NULL && NDPI_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, NDPI_PROTOCOL_YAHOO) != 0)
	     || (dst != NULL && NDPI_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, NDPI_PROTOCOL_YAHOO) != 0)) {
	    
	    NDPI_LOG_INFO(ndpi_struct, "found YAHOO HTTP GET /Messenger. match\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	}

	if((memcmp(packet->payload, "GET /", 5) == 0)) {
	  ndpi_parse_packet_line_info(ndpi_struct, flow);
	  if((packet->user_agent_line.ptr != NULL && packet->user_agent_line.len >= NDPI_STATICSTRING_LEN("YahooMobileMessenger/")
	      && memcmp(packet->user_agent_line.ptr, "YahooMobileMessenger/", NDPI_STATICSTRING_LEN("YahooMobileMessenger/")) == 0)
	     || (packet->user_agent_line.len >= 15 && (memcmp(packet->user_agent_line.ptr, "Y!%20Messenger/", 15) == 0))) {
	    
	    NDPI_LOG_INFO(ndpi_struct, "found YAHOO(Mobile)");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	  if(packet->host_line.ptr != NULL && packet->host_line.len >= NDPI_STATICSTRING_LEN("msg.yahoo.com") &&
	     memcmp(&packet->host_line.ptr[packet->host_line.len - NDPI_STATICSTRING_LEN("msg.yahoo.com")], "msg.yahoo.com", NDPI_STATICSTRING_LEN("msg.yahoo.com")) == 0) {
	    NDPI_LOG_INFO(ndpi_struct, "found YAHOO");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	}
      }
      /* found another http login command for yahoo, it is like OSCAR */
      /* detect http connections */
      if (packet->payload_packet_len > 50 && (memcmp(packet->payload, "content-length: ", 16) == 0)) {

	ndpi_parse_packet_line_info(ndpi_struct, flow);
	
	if (packet->parsed_lines > 2 && packet->line[1].len == 0) {
	  
	  NDPI_LOG_DBG(ndpi_struct, "first line is empty\n");
	  if (packet->line[2].len > 13 && memcmp(packet->line[2].ptr, "<Ymsg Command=", 14) == 0) {

	    NDPI_LOG_INFO(ndpi_struct, "YAHOO web chat found\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	}
      }

      if (packet->payload_packet_len > 38 && memcmp(packet->payload, "CONNECT scs.msg.yahoo.com:5050 HTTP/1.", 38) == 0) {
	
	NDPI_LOG_INFO(ndpi_struct, "found YAHOO-HTTP\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	return;
      }

      if ((src != NULL && NDPI_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, NDPI_PROTOCOL_YAHOO) != 0)
	  || (dst != NULL && NDPI_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, NDPI_PROTOCOL_YAHOO) != 0)) {
	if (packet->payload_packet_len == 6 && memcmp(packet->payload, "YAHOO!", 6) == 0) {
	  
	  NDPI_LOG_INFO(ndpi_struct, "found YAHOO");
	  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	  return;
	}
	/* asymmetric detection for SNDIMG not done yet.
	 * See ./Yahoo8.1-VideoCall-LAN.pcap and ./Yahoo-VideoCall-inPublicIP.pcap */

	if (packet->payload_packet_len == 8 && (memcmp(packet->payload, "<SNDIMG>", 8) == 0 || memcmp(packet->payload, "<REQIMG>", 8) == 0
						|| memcmp(packet->payload, "<RVWCFG>", 8) == 0 || memcmp(packet->payload, "<RUPCFG>", 8) == 0)) {
	  
	  if(src != NULL) {
	    if (memcmp(packet->payload, "<SNDIMG>", 8) == 0) {
	      src->yahoo_video_lan_dir = 0;
	    } else {
	      src->yahoo_video_lan_dir = 1;
	    }
	    src->yahoo_video_lan_timer = packet->tick_timestamp;
	  }
	  if(dst != NULL) {
	    if (memcmp(packet->payload, "<SNDIMG>", 8) == 0) {
	      dst->yahoo_video_lan_dir = 0;
	    } else {
	      dst->yahoo_video_lan_dir = 1;
	    }
	    dst->yahoo_video_lan_timer = packet->tick_timestamp;

	  }
	  NDPI_LOG_INFO(ndpi_struct, "found YAHOO subtype VIDEO");
	  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	  return;
	}
	if(src != NULL && packet->tcp->dest == htons(5100)
	   && ((u_int32_t) (packet->tick_timestamp - src->yahoo_video_lan_timer) < ndpi_struct->yahoo_lan_video_timeout)) {
	  
	  if (src->yahoo_video_lan_dir == 1) {

	    NDPI_LOG_INFO(ndpi_struct, "found YAHOO IMG MARKED");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	}
	if (dst != NULL && packet->tcp->dest == htons(5100)
	    && ((u_int32_t) (packet->tick_timestamp - dst->yahoo_video_lan_timer) < ndpi_struct->yahoo_lan_video_timeout)) {
	  if (dst->yahoo_video_lan_dir == 0) {
	    
	    NDPI_LOG_INFO(ndpi_struct, "found YAHOO IMG MARKED");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	}
      }
      /* detect YAHOO over HTTP proxy */
      if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP)
	{
	  if (flow->l4.tcp.yahoo_http_proxy_stage == 0) {
	    
	    NDPI_LOG_DBG2(ndpi_struct, "YAHOO maybe HTTP proxy packet 1 => need next packet\n");
	    flow->l4.tcp.yahoo_http_proxy_stage = 1 + packet->packet_direction;
	    return;
	  }
	  if (flow->l4.tcp.yahoo_http_proxy_stage == 1 + packet->packet_direction) {
	    if ((packet->payload_packet_len > 250) && (memcmp(packet->payload, "<Session ", 9) == 0)) {
	      if (ndpi_check_for_YmsgCommand(packet->payload_packet_len, packet->payload)) {
		
		NDPI_LOG_INFO(ndpi_struct, "found HTTP Proxy Yahoo Chat <Ymsg Command= pattern  \n");
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
		return;
	      }
	    }
	    NDPI_LOG_DBG2(ndpi_struct, "YAHOO maybe HTTP proxy still initial direction => need next packet\n");
	    return;
	  }
	  if (flow->l4.tcp.yahoo_http_proxy_stage == 2 - packet->packet_direction) {

	    ndpi_parse_packet_line_info_any(ndpi_struct, flow);

	    if (packet->parsed_lines >= 9) {

	      if (packet->line[4].ptr != NULL && packet->line[4].len >= 9 &&
		  packet->line[8].ptr != NULL && packet->line[8].len >= 6 &&
		  memcmp(packet->line[4].ptr, "<Session ", 9) == 0 &&
		  memcmp(packet->line[8].ptr, "<Ymsg ", 6) == 0) {

		NDPI_LOG_INFO(ndpi_struct, "found YAHOO over HTTP proxy");
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_UNKNOWN);
		return;
	      }
	    }
	  }
	}
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void ndpi_search_yahoo(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search yahoo\n");
  
  if(packet->payload_packet_len > 0 && flow->yahoo_detection_finished == 0) {

    /* search over TCP */
    if(packet->tcp != NULL && packet->tcp_retransmission == 0) {

      if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN
	 || packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP
	 || packet->detected_protocol_stack[0] == NDPI_PROTOCOL_TLS) {
        /* search over TCP */
	ndpi_search_yahoo_tcp(ndpi_struct, flow);
      }
    }
    /* search over UDP */
    else if(packet->udp != NULL) {
      if ( flow->src == NULL || 
	   NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->src->detected_protocol_bitmask, NDPI_PROTOCOL_YAHOO) == 0) {
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      }
      return;
    }
  }

  if(packet->payload_packet_len > 0 && flow->yahoo_detection_finished == 2) {
    if(packet->tcp != NULL && packet->tcp_retransmission == 0) {
      /* search over TCP */
      ndpi_search_yahoo_tcp(ndpi_struct, flow);
      return;
    }
  }
}

void init_yahoo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{

  ndpi_set_bitmask_protocol_detection("YAHOO", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_YAHOO,
				      ndpi_search_yahoo,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

