/*
 * msn.c
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

#include "ndpi_protocol_ids.h"


#ifdef NDPI_PROTOCOL_MSN

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MSN

#include "ndpi_api.h"

#define MAX_PACKETS_FOR_MSN 100

static void ndpi_int_msn_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MSN, NDPI_PROTOCOL_UNKNOWN);
}

static u_int8_t ndpi_int_find_xmsn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->parsed_lines > 3) {
    u_int16_t i;
    for(i = 2; i < packet->parsed_lines; i++) {
      if(packet->line[i].ptr != NULL && packet->line[i].len > NDPI_STATICSTRING_LEN("X-MSN") &&
	 memcmp(packet->line[i].ptr, "X-MSN", NDPI_STATICSTRING_LEN("X-MSN")) == 0) {
	return 1;
      }
    }
  }
  return 0;
}

/* search over TCP */
static void ndpi_search_msn_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  u_int16_t plen;
  u_int16_t status = 0;
  
#ifdef NDPI_PROTOCOL_SSL
  if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_SSL) {
    
    NDPI_LOG_DBG2(ndpi_struct, "msn ssl ft test\n");

    if(flow->packet_counter < 10) {
      if(flow->packet_counter == 7 && packet->payload_packet_len > 300) {
	if(memcmp(packet->payload + 24, "MSNSLP", 6) == 0
	   || (get_u_int32_t(packet->payload, 0) == htonl(0x30000000) && get_u_int32_t(packet->payload, 4) == 0x00000000)) {
	  NDPI_LOG_INFO(ndpi_struct, "found MSN File Transfer, ifdef ssl\n");
	  ndpi_int_msn_add_connection(ndpi_struct, flow);
	  return;
	}
      }
      if(flow->packet_counter >= 5 && flow->packet_counter <= 10 && (get_u_int32_t(packet->payload, 0) == htonl(0x18000000)
								     && get_u_int32_t(packet->payload, 4) == 0x00000000)) {
	flow->l4.tcp.msn_ssl_ft++;
	NDPI_LOG_DBG2(ndpi_struct,
		 "increased msn ft ssl stage to: %u at packet nr: %u\n", flow->l4.tcp.msn_ssl_ft,
		 flow->packet_counter);
	if (flow->l4.tcp.msn_ssl_ft == 2) {
	  NDPI_LOG_INFO(ndpi_struct,
		   "found MSN File Transfer, ifdef ssl 2.\n");
	  ndpi_int_msn_add_connection(ndpi_struct, flow);
	}
	return;
      }
    }
  }
#endif

  /* we detect the initial connection only ! */
  /* match: "VER " ..... "CVR" x 0x0d 0x0a
   * len should be small, lets say less than 100 bytes
   * x is now "0", but can be increased
   */
  /* now we have a look at the first packet only. */
  if(flow->packet_counter == 1
#ifdef NDPI_PROTOCOL_SSL
      || ((packet->detected_protocol_stack[0] == NDPI_PROTOCOL_SSL) && flow->packet_counter <= 3)
#endif
      ) {
    
    /* this part is working asymmetrically */
    if(packet->payload_packet_len > 32 && (packet->payload[0] == 0x02 || packet->payload[0] == 0x00)
       && (ntohl(get_u_int32_t(packet->payload, 8)) == 0x2112a442 || ntohl(get_u_int32_t(packet->payload, 4)) == 0x2112a442)
       && ((ntohl(get_u_int32_t(packet->payload, 24)) == 0x000f0004 && ntohl(get_u_int32_t(packet->payload, 28)) == 0x72c64bc6)
	   || (ntohl(get_u_int32_t(packet->payload, 20)) == 0x000f0004
	       && ntohl(get_u_int32_t(packet->payload, 24)) == 0x72c64bc6))) {
      NDPI_LOG_INFO(ndpi_struct,
	       "found MSN in packets that also contain voice.messenger.live.com.\n");

      /* TODO this is an alternative pattern for video detection */
      /*          if (packet->payload_packet_len > 100 &&
		  get_u_int16_t(packet->payload, 86) == htons(0x05dc)) { */
      ndpi_int_msn_add_connection(ndpi_struct, flow);
      return;
    }

    /* this case works asymmetrically */
    if (packet->payload_packet_len > 10 && packet->payload_packet_len < 100) {
      if (get_u_int8_t(packet->payload, packet->payload_packet_len - 2) == 0x0d
	  && get_u_int8_t(packet->payload, packet->payload_packet_len - 1) == 0x0a) {
	/* The MSNP string is used in XBOX clients. */
	if (ndpi_match_strprefix(packet->payload, packet->payload_packet_len, "VER ")) {

	  if (memcmp(&packet->payload[packet->payload_packet_len - 6], "CVR",
		     3) == 0 || memcmp(&packet->payload[packet->payload_packet_len - 8], "MSNP", 4) == 0) {
	    NDPI_LOG_INFO(ndpi_struct, "found MSN by pattern VER...CVR/MSNP ODOA\n");
	    ndpi_int_msn_add_connection(ndpi_struct, flow);
	    return;
	  }
	  if (ndpi_match_strprefix(&packet->payload[4], packet->payload_packet_len-4, "MSNFT")) {
	    NDPI_LOG_INFO(ndpi_struct, "found MSN FT by pattern VER MSNFT...0d0a\n");
	    ndpi_int_msn_add_connection(ndpi_struct, flow);
	    return;
	  }
	}
      }
    }
    if(
#ifdef NDPI_PROTOCOL_HTTP
       packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
#endif
       ndpi_match_strprefix(packet->payload, packet->payload_packet_len, "GET ") ||
       ndpi_match_strprefix(packet->payload, packet->payload_packet_len, "POST ")) {
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      if (packet->user_agent_line.ptr != NULL &&
	  packet->user_agent_line.len > NDPI_STATICSTRING_LEN("Messenger/") &&
	  memcmp(packet->user_agent_line.ptr, "Messenger/", NDPI_STATICSTRING_LEN("Messenger/")) == 0) {
	NDPI_LOG_INFO(ndpi_struct, "found MSN Messenger/\n");
	ndpi_int_msn_add_connection(ndpi_struct, flow);
	return;
      }
    }
/* #ifdef NDPI_PROTOCOL_HTTP */
/*     /\* we have to examine two http packets *\/ */
/*     if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP) { */
/*     } */
/* #endif */
    /* not seen this pattern in any trace */
    /* now test for http login, at least 100 a bytes packet */
    if(packet->payload_packet_len > 100) {
      if(
#ifdef NDPI_PROTOCOL_HTTP
	  packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
#endif
	  memcmp(packet->payload, "POST http://", 12) == 0) {
	/* scan packet if not already done... */
	ndpi_parse_packet_line_info(ndpi_struct, flow);
	
	if(packet->content_line.ptr != NULL &&
	   ((packet->content_line.len == NDPI_STATICSTRING_LEN("application/x-msn-messenger") &&
	     memcmp(packet->content_line.ptr, "application/x-msn-messenger",
		    NDPI_STATICSTRING_LEN("application/x-msn-messenger")) == 0) ||
	    (packet->content_line.len >= NDPI_STATICSTRING_LEN("text/x-msnmsgr") &&
	     memcmp(packet->content_line.ptr, "text/x-msnmsgr",
		    NDPI_STATICSTRING_LEN("text/x-msnmsgr")) == 0))) {
	  NDPI_LOG_INFO(ndpi_struct, "found MSN POST application/x-msn-messenger\n");
	  ndpi_int_msn_add_connection(ndpi_struct, flow);
	  return;
	}
      }
    }
    /* now test for http login that uses a gateway, at least 400 a bytes packet */
    /* for this case the asymmetric detection is asym (1) */
    if(packet->payload_packet_len > 400) {
      if((
#ifdef NDPI_PROTOCOL_HTTP
	  packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
#endif
	  (memcmp(packet->payload, "POST ", 5) == 0))) {
	u_int16_t c;
	if(memcmp(&packet->payload[5], "http://", 7) == 0) {
	  /*
	   * We are searching for a pattern "POST http://gateway.messenger.hotmail.com/gateway/gateway.dll" or
	   * "POST http://<some ip address here like 172.0.0.0>/gateway/gateway.dll"
	   * POST http:// is 12 byte so we are searching for 13 to 70 byte for this paten.
	   */
	  for(c = 13; c < 50; c++) {
	    if(memcmp(&packet->payload[c], "/", 1) == 0) {
	      if(memcmp(&packet->payload[c], "/gateway/gateway.dll", 20) == 0) {
		NDPI_LOG_DBG2(ndpi_struct, "found  pattern http://.../gateway/gateway.ddl\n");
		status = 1;
		break;
	      }
	    }
	  }
	} else if((memcmp(&packet->payload[5], "/gateway/gateway.dll", 20) == 0)) {
	  NDPI_LOG_DBG2(ndpi_struct, "found  pattern http://.../gateway/gateway.ddl\n");
	  status = 1;
	}
      }
      if(status) {
	u_int16_t a;
	
	ndpi_parse_packet_line_info(ndpi_struct, flow);

	if(packet->content_line.ptr != NULL && ((packet->content_line.len == 23
						 && memcmp(packet->content_line.ptr, "text/xml; charset=utf-8", 23) == 0)
						||
						(packet->content_line.len == 24
						 && memcmp(packet->content_line.ptr, "text/html; charset=utf-8", 24) == 0)
						||
						(packet->content_line.len == 33
						 && memcmp(packet->content_line.ptr, "application/x-www-form-urlencoded", 33) == 0))) {
	  
	  if ((src != NULL && NDPI_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, NDPI_PROTOCOL_MSN) != 0)
	      || (dst != NULL && NDPI_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, NDPI_PROTOCOL_MSN) != 0)) {
	    
	    NDPI_LOG_INFO(ndpi_struct, "found MSN with pattern text/xml; charset=utf-8\n");
	    ndpi_int_msn_add_connection(ndpi_struct, flow);
	    return;
	  }
	  for(a = 0; a < packet->parsed_lines; a++) {
	    if(packet->line[a].len >= 4 && (memcmp(packet->line[a].ptr, "CVR ", 4) == 0
					    || memcmp(packet->line[a].ptr, "VER ", 4) == 0 ||
					    memcmp(packet->line[a].ptr, "ANS ", 4) == 0)) {
	      
	      NDPI_LOG_DBG2(ndpi_struct, "found MSN with pattern text/sml; charset0utf-8\n");
	      NDPI_LOG_INFO(ndpi_struct, "found MSN xml CVS / VER / ANS found\n");
	      ndpi_int_msn_add_connection(ndpi_struct, flow);
	      return;
	    }
	  }
	}
      }
    }
    /* asym (1) ; possibly occurs in symmetric cases also. */
    if(flow->packet_counter <= 10 &&
       (flow->packet_direction_counter[0] <= 2 || flow->packet_direction_counter[1] <= 2)
       && packet->payload_packet_len > 100) {
      /* not necessary to check the length, because this has been done : >400. */
      if(
#ifdef NDPI_PROTOCOL_HTTP
	 packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
#endif
	 ndpi_match_strprefix(packet->payload, packet->payload_packet_len, "HTTP/1.0 200 OK") ||
	 ndpi_match_strprefix(packet->payload, packet->payload_packet_len, "HTTP/1.1 200 OK")
	 ) {
	
	ndpi_parse_packet_line_info(ndpi_struct, flow);

	if(packet->content_line.ptr != NULL &&
	    ((packet->content_line.len == NDPI_STATICSTRING_LEN("application/x-msn-messenger") &&
	      memcmp(packet->content_line.ptr, "application/x-msn-messenger", NDPI_STATICSTRING_LEN("application/x-msn-messenger")) == 0) ||
	     (packet->content_line.len >= NDPI_STATICSTRING_LEN("text/x-msnmsgr") &&
	      memcmp(packet->content_line.ptr, "text/x-msnmsgr", NDPI_STATICSTRING_LEN("text/x-msnmsgr")) == 0))) {
	  
	  NDPI_LOG_INFO(ndpi_struct,
		   "found MSN  application/x-msn-messenger.\n");
	  ndpi_int_msn_add_connection(ndpi_struct, flow);
	  return;
	}
	if(ndpi_int_find_xmsn(ndpi_struct, flow) == 1) {
	  NDPI_LOG_INFO(ndpi_struct, "found MSN X-MSN\n");
	  ndpi_int_msn_add_connection(ndpi_struct, flow);
	  return;
	}
      }
    }
    /* did not find any trace with this pattern */
    /* now block proxy connection */
    if(packet->payload_packet_len >= 42) {
      if(memcmp(packet->payload, "CONNECT messenger.hotmail.com:1863 HTTP/1.", 42) == 0) {
	NDPI_LOG_INFO(ndpi_struct, "found MSN  with pattern CONNECT messenger.hotmail.com:1863 HTTP/1.\n");
	ndpi_int_msn_add_connection(ndpi_struct, flow);
	return;
      }
    }
    if (packet->payload_packet_len >= 18) {

      if (memcmp(packet->payload, "USR ", 4) == 0 || memcmp(packet->payload, "ANS ", 4) == 0) {
	/* now we must see a number */
	const u_int16_t endlen = packet->payload_packet_len - 12;
	plen = 4;
	while (1) {
	  if (packet->payload[plen] == ' ') {
	    break;
	  }
	  if (packet->payload[plen] < '0' || packet->payload[plen] > '9') {
	    goto ndpi_msn_exclude;
	  }
	  plen++;
	  if (plen >= endlen) {
	    goto ndpi_msn_exclude;
	  }
	}

	while (plen < endlen) {
	  if (ndpi_check_for_email_address(ndpi_struct, flow, plen) != 0) {
	    NDPI_LOG_DBG2(ndpi_struct, "found mail address\n");
	    break;
	  }
	  if (packet->payload_packet_len > plen + 1
	      && (packet->payload[plen] < 20 || packet->payload[plen] > 128)) {
	    goto ndpi_msn_exclude;
	  }
	  plen++;
	  if (plen >= endlen) {
	    goto ndpi_msn_exclude;
	  }
	}
	NDPI_LOG_INFO(ndpi_struct, "found MSN  with pattern USR/ANS ...mail_address\n");
	ndpi_int_msn_add_connection(ndpi_struct, flow);
	return;
      }
    }
  }
  /* finished examining the first packet only. */

  /* asym (1) ; possibly occurs in symmetric cases also. */
  if(flow->packet_counter <= 10 &&
      (flow->packet_direction_counter[0] <= 2 || flow->packet_direction_counter[1] <= 2) &&
      packet->payload_packet_len > 100) {
    /* not necessary to check the length, because this has been done : >400. */
    if(
#ifdef NDPI_PROTOCOL_HTTP
       packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
#endif
       (memcmp(packet->payload, "HTTP/1.0 200 OK", 15) == 0) ||
       (memcmp(packet->payload, "HTTP/1.1 200 OK", 15) == 0)) {
      
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      
      if(packet->content_line.ptr != NULL && ((packet->content_line.len == NDPI_STATICSTRING_LEN("application/x-msn-messenger") &&
					       memcmp(packet->content_line.ptr, "application/x-msn-messenger",
						      NDPI_STATICSTRING_LEN("application/x-msn-messenger")) == 0) ||
					      (packet->content_line.len >= NDPI_STATICSTRING_LEN("text/x-msnmsgr") &&
					       memcmp(packet->content_line.ptr, "text/x-msnmsgr", NDPI_STATICSTRING_LEN("text/x-msnmsgr")) == 0))) {
	
	NDPI_LOG_INFO(ndpi_struct, "found MSN application/x-msn-messenger\n");
	ndpi_int_msn_add_connection(ndpi_struct, flow);
	return;
      }
      if(ndpi_int_find_xmsn(ndpi_struct, flow) == 1) {
	NDPI_LOG_INFO(ndpi_struct, "found MSN X-MSN\n");
	ndpi_int_msn_add_connection(ndpi_struct, flow);
	return;
      }
    }
  }
  /* finished examining the second packet only */
  /* direct user connection (file transfer,...) */
  
  if((src != NULL && NDPI_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, NDPI_PROTOCOL_MSN) != 0)
     || (dst != NULL
	 && NDPI_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, NDPI_PROTOCOL_MSN) != 0)) {
    if (flow->packet_counter == 1 &&
	packet->payload_packet_len > 12 && memcmp(packet->payload, "recipientid=", 12) == 0) {
      NDPI_LOG_INFO(ndpi_struct, "found MSN file transfer\n");
      ndpi_int_msn_add_connection(ndpi_struct, flow);
      return;
    }
  }
  /* MSN File Transfer of MSN 8.1 and 8.5
   * first packet with length 4 and pattern 0x04000000
   * second packet (in the same direction), with length 56 and pattern 0x00000000 from payload[16]
   * third packet (in the opposite direction to 1 & 2), with length 4 and pattern 0x30000000
   */
  if(flow->l4.tcp.msn_stage == 0) {
    /* asymmetric detection to this pattern is asym (2) */
    if((packet->payload_packet_len == 4 || packet->payload_packet_len == 8)
       && get_u_int32_t(packet->payload, 0) == htonl(0x04000000)) {
      
      NDPI_LOG_DBG2(ndpi_struct, "maybe first TCP MSN detected\n");
      
      if(packet->payload_packet_len == 8 && get_u_int32_t(packet->payload, 4) == htonl(0x666f6f00)) {
	flow->l4.tcp.msn_stage = 5 + packet->packet_direction;
	return;
      }
      flow->l4.tcp.msn_stage = 1 + packet->packet_direction;
      return;
    }
    /* asymmetric detection to this pattern is asym (2) */
  } else if (flow->l4.tcp.msn_stage == 1 + packet->packet_direction) {
    if (packet->payload_packet_len > 10 && get_u_int32_t(packet->payload, 0) == htonl(0x666f6f00)) {
      ndpi_int_msn_add_connection(ndpi_struct, flow);
      NDPI_LOG_INFO(ndpi_struct, "found MSN File Transfer 1\n");
      return;
    }
    /* did not see this pattern in any trace */
    if (packet->payload_packet_len == 56 && get_u_int32_t(packet->payload, 16) == 0) {
      NDPI_LOG_DBG2(ndpi_struct, "maybe Second TCP MSN detected\n");
      flow->l4.tcp.msn_stage = 3 + packet->packet_direction;
      return;
    }


  } else if (flow->l4.tcp.msn_stage == 2 - packet->packet_direction
	     && packet->payload_packet_len == 4 && get_u_int32_t(packet->payload, 0) == htonl(0x30000000)) {
    ndpi_int_msn_add_connection(ndpi_struct, flow);
    NDPI_LOG_INFO(ndpi_struct, "found MSN File Transfer 2\n");
    return;
  } else if ((flow->l4.tcp.msn_stage == 3 + packet->packet_direction)
	     || (flow->l4.tcp.msn_stage == 4 - packet->packet_direction)) {
    if (packet->payload_packet_len == 4 && get_u_int32_t(packet->payload, 0) == htonl(0x30000000)) {
      ndpi_int_msn_add_connection(ndpi_struct, flow);
      NDPI_LOG_INFO(ndpi_struct, "found MSN File Transfer 2\n");
      return;
    }
  } else if (flow->l4.tcp.msn_stage == 6 - packet->packet_direction) {
    if ((packet->payload_packet_len == 4) &&
	(get_u_int32_t(packet->payload, 0) == htonl(0x10000000) || get_u_int32_t(packet->payload, 0) == htonl(0x30000000))) {
      ndpi_int_msn_add_connection(ndpi_struct, flow);
      NDPI_LOG_INFO(ndpi_struct, "found MSN File Transfer 3\n");
      return;
    }
  } else if (flow->l4.tcp.msn_stage == 5 + packet->packet_direction) {
    if ((packet->payload_packet_len == 20) && get_u_int32_t(packet->payload, 0) == htonl(0x10000000)) {
      ndpi_int_msn_add_connection(ndpi_struct, flow);
      NDPI_LOG_INFO(ndpi_struct, "found MSN File Transfer 3\n");
      return;
    }
  }
  NDPI_LOG_DBG(ndpi_struct, "msn 7\n");
  
  if (flow->packet_counter <= MAX_PACKETS_FOR_MSN) {	
    if (memcmp(&packet->payload[0], "MSG ", 4) == 0
	|| memcmp(&packet->payload[0], "PNG", 3) == 0
	|| memcmp(&packet->payload[0], "QNG ", 4) == 0
	|| memcmp(&packet->payload[0], "OUT", 3) == 0
	|| memcmp(&packet->payload[0], "RNG ", 4) == 0
	|| memcmp(&packet->payload[0], "NLN ", 4) == 0
	|| memcmp(&packet->payload[0], "UBX ", 4) == 0
	|| memcmp(&packet->payload[0], "XFR ", 4) == 0) {
      ndpi_int_msn_add_connection(ndpi_struct, flow);
      
      NDPI_LOG_INFO(ndpi_struct, "found MSN\n");
      return;
    }
  }
 ndpi_msn_exclude:
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* search over UDP */
static void ndpi_search_msn_udp_misc(struct ndpi_detection_module_struct
				     *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;


  /* do we have an msn login ? */
  if ((src == NULL || NDPI_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, NDPI_PROTOCOL_MSN) == 0)
      && (dst == NULL
	  || NDPI_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, NDPI_PROTOCOL_MSN) == 0)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /* asymmetric ft detection works */
  if (packet->payload_packet_len == 20
      && get_u_int32_t(packet->payload, 4) == 0 && packet->payload[9] == 0
      && get_u_int16_t(packet->payload, 10) == htons(0x0100)) {
    NDPI_LOG_INFO(ndpi_struct, "found MSN udp misc data connection\n");
    ndpi_int_msn_add_connection(ndpi_struct, flow);
  }

  /* asymmetric detection working. */
  return;
  //}
}


void ndpi_search_msn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search msn\n");
  /* this if request should always be true */
  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MSN) == 0) {
    /* we deal with tcp now */
    if(packet->tcp != NULL) {
      /* msn can use http or ssl for connection. That's why every http, ssl and ukn packet must enter in the msn detection */
      /* the detection can switch out the http or the ssl detection. In this case we need not check those protocols */
      // need to do the ceck when protocol == http too (POST /gateway ...)
      if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN
#ifdef NDPI_PROTOCOL_HTTP
	 || packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP
#endif
#ifdef NDPI_PROTOCOL_SSL
	 || packet->detected_protocol_stack[0] == NDPI_PROTOCOL_SSL
#endif
#ifdef NDPI_PROTOCOL_STUN
	 || packet->detected_protocol_stack[0] == NDPI_PROTOCOL_STUN
#endif
	 )
	ndpi_search_msn_tcp(ndpi_struct, flow);
    } else if (packet->udp != NULL) {
      ndpi_search_msn_udp_misc(ndpi_struct, flow);
    }
  }
}


void init_msn_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) 
{
  
  NDPI_BITMASK_RESET(ndpi_struct->callback_buffer[*id].excluded_protocol_bitmask);
  
  ndpi_set_bitmask_protocol_detection("MSN", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MSN,
				      ndpi_search_msn,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
