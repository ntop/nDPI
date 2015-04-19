/*
 * http.c
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

#ifdef NDPI_PROTOCOL_HTTP

static void ndpi_int_http_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow,
					 u_int32_t protocol) {

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
    /* This is HTTP and it is not a sub protocol (e.g. skype or dropbox) */

    ndpi_search_tcp_or_udp(ndpi_struct, flow);

    /* If no custom protocol has been detected */
    if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
      if(protocol != NDPI_PROTOCOL_HTTP) {
	ndpi_search_tcp_or_udp(ndpi_struct, flow);
	ndpi_int_add_connection(ndpi_struct, flow, protocol, NDPI_CORRELATED_PROTOCOL);
      } else {
	ndpi_int_reset_protocol(flow);
	ndpi_int_add_connection(ndpi_struct, flow, protocol, NDPI_REAL_PROTOCOL);
      }
    }

    flow->http_detected = 1;
  }

}

#ifdef NDPI_CONTENT_FLASH
static void flash_check_http_payload(struct ndpi_detection_module_struct
				     *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  const u_int8_t *pos;

  if(packet->empty_line_position_set == 0 || (packet->empty_line_position + 10) > (packet->payload_packet_len))
    return;

  pos = &packet->payload[packet->empty_line_position] + 2;


  if(memcmp(pos, "FLV", 3) == 0 && pos[3] == 0x01 && (pos[4] == 0x01 || pos[4] == 0x04 || pos[4] == 0x05)
     && pos[5] == 0x00 && pos[6] == 0x00 && pos[7] == 0x00 && pos[8] == 0x09) {

    NDPI_LOG(NDPI_CONTENT_FLASH, ndpi_struct, NDPI_LOG_DEBUG, "Flash content in http detected\n");
    ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_CONTENT_FLASH);
  }
}
#endif

#ifdef NDPI_CONTENT_AVI
static void avi_check_http_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;


  NDPI_LOG(NDPI_CONTENT_AVI, ndpi_struct, NDPI_LOG_DEBUG, "called avi_check_http_payload: %u %u %u\n",
	   packet->empty_line_position_set, flow->l4.tcp.http_empty_line_seen, packet->empty_line_position);

  if(packet->empty_line_position_set == 0 && flow->l4.tcp.http_empty_line_seen == 0)
    return;

  if(packet->empty_line_position_set != 0 && ((packet->empty_line_position + 20) > (packet->payload_packet_len))
     && flow->l4.tcp.http_empty_line_seen == 0) {
    flow->l4.tcp.http_empty_line_seen = 1;
    return;
  }

  if(flow->l4.tcp.http_empty_line_seen == 1) {
    if(packet->payload_packet_len > 20 && memcmp(packet->payload, "RIFF", 4) == 0
       && memcmp(packet->payload + 8, "AVI LIST", 8) == 0) {
      NDPI_LOG(NDPI_CONTENT_AVI, ndpi_struct, NDPI_LOG_DEBUG, "Avi content in http detected\n");
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_CONTENT_AVI);
    }
    flow->l4.tcp.http_empty_line_seen = 0;
    return;
  }

  if(packet->empty_line_position_set != 0) {
    // check for avi header
    // for reference see http://msdn.microsoft.com/archive/default.asp?url=/archive/en-us/directx9_c/directx/htm/avirifffilereference.asp
    u_int32_t p = packet->empty_line_position + 2;

    NDPI_LOG(NDPI_CONTENT_AVI, ndpi_struct, NDPI_LOG_DEBUG, "p = %u\n", p);

    if((p + 16) <= packet->payload_packet_len && memcmp(&packet->payload[p], "RIFF", 4) == 0
       && memcmp(&packet->payload[p + 8], "AVI LIST", 8) == 0) {
      NDPI_LOG(NDPI_CONTENT_AVI, ndpi_struct, NDPI_LOG_DEBUG, "Avi content in http detected\n");
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_CONTENT_AVI);
    }
  }
}
#endif

#ifdef NDPI_PROTOCOL_TEAMVIEWER
static void teamviewer_check_http_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  const u_int8_t *pos;

  NDPI_LOG(NDPI_PROTOCOL_TEAMVIEWER, ndpi_struct, NDPI_LOG_DEBUG, "called teamviewer_check_http_payload: %u %u %u\n",
	   packet->empty_line_position_set, flow->l4.tcp.http_empty_line_seen, packet->empty_line_position);

  if(packet->empty_line_position_set == 0 || (packet->empty_line_position + 5) > (packet->payload_packet_len))
    return;

  pos = &packet->payload[packet->empty_line_position] + 2;

  if(pos[0] == 0x17 && pos[1] == 0x24) {
    NDPI_LOG(NDPI_PROTOCOL_TEAMVIEWER, ndpi_struct, NDPI_LOG_DEBUG, "TeamViewer content in http detected\n");
    ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TEAMVIEWER);
  }
}
#endif


#ifdef NDPI_PROTOCOL_RTSP
static void rtsp_parse_packet_acceptline(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->accept_line.len >= 28 && memcmp(packet->accept_line.ptr, "application/x-rtsp-tunnelled", 28) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_RTSP, ndpi_struct, NDPI_LOG_DEBUG, "RTSP accept line detected\n");
    ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RTSP);
  }
}
#endif

static void setHttpUserAgent(struct ndpi_flow_struct *flow, char *ua) {
  if(!strcmp(ua, "Windows NT 5.0")) ua = "Windows 2000";
  else if(!strcmp(ua, "Windows NT 5.1")) ua = "Windows XP";
  else if(!strcmp(ua, "Windows NT 5.2")) ua = "Windows Server 2003";
  else if(!strcmp(ua, "Windows NT 6.0")) ua = "Windows Vista";
  // else if(!strcmp(ua, "Windows NT 7.0")) ua = "Windows 7";
  else if(!strcmp(ua, "Windows NT 6.1")) ua = "Windows 7";
  else if(!strcmp(ua, "Windows NT 6.2")) ua = "Windows 8";
  else if(!strcmp(ua, "Windows NT 6.3")) ua = "Windows 8.1";

  //printf("==> %s\n", ua);
  snprintf((char*)flow->detected_os, sizeof(flow->detected_os), "%s", ua);
}

static void parseHttpSubprotocol(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  // int i = 0;
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->iph /* IPv4 only */) {
    /*
      Twitter Inc. TWITTER-NETWORK (NET-199-59-148-0-1) 199.59.148.0 - 199.59.151.255
      199.59.148.0/22
    */
    if(((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC73B9400 /* 199.59.148.0 */)
       || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC73B9400 /* 199.59.148.0 */)) {
      packet->detected_protocol_stack[0] = NDPI_SERVICE_TWITTER;
      return;
    }

    /*
      CIDR:           69.53.224.0/19
      OriginAS:       AS2906
      NetName:        NETFLIX-INC
    */
    if(((ntohl(packet->iph->saddr) & 0xFFFFE000 /* 255.255.224.0 */) == 0x4535E000 /* 69.53.224.0 */)
       || ((ntohl(packet->iph->daddr) & 0xFFFFE000 /* 255.255.224.0 */) == 0x4535E000 /* 69.53.224.0 */)) {
      packet->detected_protocol_stack[0] = NDPI_SERVICE_NETFLIX;
      return;
    }
  }

  if((flow->l4.tcp.http_stage == 0)
     || (flow->http.url && flow->http_detected)) {
      /* Try matching subprotocols */
      // ndpi_match_string_subprotocol(ndpi_struct, flow, (char*)packet->host_line.ptr, packet->host_line.len);

      if(ndpi_struct->http_dissect_response) {
	if(flow->http.url && flow->http_detected)
	  ndpi_match_string_subprotocol(ndpi_struct, flow, (char *)&flow->http.url[7], strlen((const char *)&flow->http.url[7]));
      } else
	ndpi_match_string_subprotocol(ndpi_struct, flow, (char *)flow->host_server_name, strlen((const char *)flow->host_server_name));
    }
}

/*
  NOTE

  ndpi_parse_packet_line_info @ ndpi_main.c
  is the code that parses the packet
*/
static void check_content_type_and_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						   struct ndpi_flow_struct *flow) {
#ifdef NDPI_CONTENT_MPEG
  struct ndpi_packet_struct *packet = &flow->packet;
#endif
#ifdef NDPI_CONTENT_AVI
#endif
  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  u_int8_t a;

  if(ndpi_struct->http_dissect_response) {
    if((flow->http.url == NULL)
       && (packet->http_url_name.len > 0)
       && (packet->host_line.len > 0)) {
      int len = packet->http_url_name.len + packet->host_line.len + 7 + 1; /* "http://" */

      flow->http.url = ndpi_malloc(len);
      if(flow->http.url) {
	strncpy(flow->http.url, "http://", 7);
	strncpy(&flow->http.url[7], (char*)packet->host_line.ptr, packet->host_line.len);
	strncpy(&flow->http.url[7+packet->host_line.len], (char*)packet->http_url_name.ptr, 
		packet->http_url_name.len);
	flow->http.url[len-1] = '\0';
      }

      if(flow->packet.http_method.len < 3)
	flow->http.method = HTTP_METHOD_UNKNOWN;
      else {
	switch(flow->packet.http_method.ptr[0]) {
	case 'O':  flow->http.method = HTTP_METHOD_OPTIONS; break;
	case 'G':  flow->http.method = HTTP_METHOD_GET; break;
	case 'H':  flow->http.method = HTTP_METHOD_HEAD; break;

	case 'P':
	  switch(flow->packet.http_method.ptr[1]) {
	  case 'O': flow->http.method = HTTP_METHOD_POST; break;
	  case 'U': flow->http.method = HTTP_METHOD_PUT; break;
	  }
	  break;

	case 'D':   flow->http.method = HTTP_METHOD_DELETE; break;
	case 'T':   flow->http.method = HTTP_METHOD_TRACE; break;
	case 'C':   flow->http.method = HTTP_METHOD_CONNECT; break;
	default:
	  flow->http.method = HTTP_METHOD_UNKNOWN;
	  break;
	}
      }
    }

    if((flow->http.content_type == NULL) && (packet->content_line.len > 0)) {
      int len = packet->content_line.len + 1;

      flow->http.content_type = ndpi_malloc(len);
      if(flow->http.content_type) {
	strncpy(flow->http.content_type, (char*)packet->content_line.ptr, 
		packet->content_line.len);      
	flow->http.content_type[packet->content_line.len] = '\0';
      }
    }
  }

  if(packet->user_agent_line.ptr != NULL && packet->user_agent_line.len != 0) {
    /* Format:
       Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) ....
    */
    if(packet->user_agent_line.len > 7) {
      char ua[256];
      u_int mlen = ndpi_min(packet->user_agent_line.len, sizeof(ua)-1);

      strncpy(ua, (const char *)packet->user_agent_line.ptr, mlen);
      ua[mlen] = '\0';

      if(strncmp(ua, "Mozilla", 7) == 0) {
	char *parent = strchr(ua, '(');

	if(parent) {
	  char *token, *end;

	  parent++;
	  end = strchr(parent, ')');
	  if(end) end[0] = '\0';

	  token = strsep(&parent, ";");
	  if(token) {
	    if((strcmp(token, "X11") == 0)
	       || (strcmp(token, "compatible") == 0)
	       || (strcmp(token, "Linux") == 0)
	       || (strcmp(token, "Macintosh") == 0)
	       ) {
	      token = strsep(&parent, ";");
	      if(token && (token[0] == ' ')) token++; /* Skip space */

	      if(token
		 && ((strcmp(token, "U") == 0)
		     || (strncmp(token, "MSIE", 4) == 0))) {
		token = strsep(&parent, ";");
		if(token && (token[0] == ' ')) token++; /* Skip space */

		if(token && (strncmp(token, "Update", 6)  == 0)) {
		  token = strsep(&parent, ";");

		  if(token && (token[0] == ' ')) token++; /* Skip space */

		  if(token && (strncmp(token, "AOL", 3)  == 0)) {
		    token = strsep(&parent, ";");

		    if(token && (token[0] == ' ')) token++; /* Skip space */
		  }
		}
	      }
	    }

	    if(token)
	      setHttpUserAgent(flow, token);
	  }
	}
      }
    }

    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "User Agent Type Line found %.*s\n",
	     packet->user_agent_line.len, packet->user_agent_line.ptr);

    if((!ndpi_struct->http_dissect_response) || flow->http_detected)
      ndpi_match_content_subprotocol(ndpi_struct, flow, 
				     (char*)packet->user_agent_line.ptr, 
				     packet->user_agent_line.len);
  }

  /* check for host line */
  if(packet->host_line.ptr != NULL) {
    u_int len;

    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HOST Line found %.*s\n",
	     packet->host_line.len, packet->host_line.ptr);

    if((!ndpi_struct->http_dissect_response) || flow->http_detected)
      ndpi_match_content_subprotocol(ndpi_struct, flow, 
				     (char*)packet->host_line.ptr, 
				     packet->host_line.len);

    /* Copy result for nDPI apps */
    len = ndpi_min(packet->host_line.len, sizeof(flow->host_server_name)-1);
    strncpy((char*)flow->host_server_name, (char*)packet->host_line.ptr, len);
    flow->host_server_name[len] = '\0', flow->server_id = flow->dst;

    len = ndpi_min(packet->forwarded_line.len, sizeof(flow->nat_ip)-1);
    strncpy((char*)flow->nat_ip, (char*)packet->forwarded_line.ptr, len);
    flow->nat_ip[len] = '\0';

    if(!ndpi_struct->http_dissect_response)
      parseHttpSubprotocol(ndpi_struct, flow);

    if((flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
       && ((!ndpi_struct->http_dissect_response) || flow->http_detected))
      ndpi_match_string_subprotocol(ndpi_struct, flow,
				    (char *)flow->host_server_name,
				    strlen((const char *)flow->host_server_name));

    if((flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
       && ((!ndpi_struct->http_dissect_response) || flow->http_detected)
       && (packet->http_origin.len > 0))
      ndpi_match_string_subprotocol(ndpi_struct, flow,
				    (char *)packet->http_origin.ptr,
				    packet->http_origin.len);

    if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
      if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
	ndpi_int_http_add_connection(ndpi_struct, flow, packet->detected_protocol_stack[0]);
	return; /* We have identified a sub-protocol so we're done */
      }
    }
  }

  if(ndpi_struct->http_dissect_response && flow->http_detected)
    parseHttpSubprotocol(ndpi_struct, flow);

  /* check for accept line */
  if(packet->accept_line.ptr != NULL) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "Accept Line found %.*s\n",
	     packet->accept_line.len, packet->accept_line.ptr);
#ifdef NDPI_PROTOCOL_RTSP
    if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_RTSP) != 0) {
      rtsp_parse_packet_acceptline(ndpi_struct, flow);
    }
#endif
  }

  /* search for line startin with "Icy-MetaData" */
#ifdef NDPI_CONTENT_MPEG
  for (a = 0; a < packet->parsed_lines; a++) {
    if(packet->line[a].len > 11 && memcmp(packet->line[a].ptr, "Icy-MetaData", 12) == 0) {
      NDPI_LOG(NDPI_CONTENT_MPEG, ndpi_struct, NDPI_LOG_DEBUG, "MPEG: Icy-MetaData found.\n");
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_CONTENT_MPEG);
      return;
    }
  }
#ifdef NDPI_CONTENT_AVI
#endif
#endif

  if(packet->content_line.ptr != NULL && packet->content_line.len != 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "Content Type Line found %.*s\n",
	     packet->content_line.len, packet->content_line.ptr);

    if((!ndpi_struct->http_dissect_response) || flow->http_detected)
      ndpi_match_content_subprotocol(ndpi_struct, flow, (char*)packet->content_line.ptr, packet->content_line.len);
  }

  /* check user agent here too */
}

static void check_http_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "called check_http_payload.\n");

#ifdef NDPI_CONTENT_FLASH
  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_CONTENT_FLASH) != 0)
    flash_check_http_payload(ndpi_struct, flow);
#endif
#ifdef NDPI_CONTENT_AVI
  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_CONTENT_AVI) != 0)
    avi_check_http_payload(ndpi_struct, flow);
#endif
#ifdef NDPI_PROTOCOL_TEAMVIEWER
  teamviewer_check_http_payload(ndpi_struct, flow);
#endif

}

/**
 * this functions checks whether the packet begins with a valid http request
 * @param ndpi_struct
 * @returnvalue 0 if no valid request has been found
 * @returnvalue >0 indicates start of filename but not necessarily in packet limit
 */
static u_int16_t http_request_url_offset(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "====>>>> HTTP: %c%c%c%c [len: %u]\n",
	   packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3],
	   packet->payload_packet_len);

  /* FIRST PAYLOAD PACKET FROM CLIENT */
  /* check if the packet starts with POST or GET */
  if(packet->payload_packet_len >= 4 && memcmp(packet->payload, "GET ", 4) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: GET FOUND\n");
    return 4;
  } else if(packet->payload_packet_len >= 5 && memcmp(packet->payload, "POST ", 5) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: POST FOUND\n");
    return 5;
  } else if(packet->payload_packet_len >= 8 && memcmp(packet->payload, "OPTIONS ", 8) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: OPTIONS FOUND\n");
    return 8;
  } else if(packet->payload_packet_len >= 5 && memcmp(packet->payload, "HEAD ", 5) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: HEAD FOUND\n");
    return 5;
  } else if(packet->payload_packet_len >= 4 && memcmp(packet->payload, "PUT ", 4) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: PUT FOUND\n");
    return 4;
  } else if(packet->payload_packet_len >= 7 && memcmp(packet->payload, "DELETE ", 7) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: DELETE FOUND\n");
    return 7;
  } else if(packet->payload_packet_len >= 8 && memcmp(packet->payload, "CONNECT ", 8) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: CONNECT FOUND\n");
    return 8;
  } else if(packet->payload_packet_len >= 9 && memcmp(packet->payload, "PROPFIND ", 9) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: PROFIND FOUND\n");
    return 9;
  } else if(packet->payload_packet_len >= 7 && memcmp(packet->payload, "REPORT ", 7) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: REPORT FOUND\n");
    return 7;
  }

  return 0;
}

static void http_bitmask_exclude(struct ndpi_flow_struct *flow)
{
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HTTP);
#ifdef NDPI_PROTOCOL_WINDOWS_UPDATE
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_WINDOWS_UPDATE);
#endif
#ifdef NDPI_CONTENT_MPEG
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_CONTENT_MPEG);
#endif
#ifdef NDPI_CONTENT_QUICKTIME
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_CONTENT_QUICKTIME);
#endif
#ifdef NDPI_CONTENT_WINDOWSMEDIA
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_CONTENT_WINDOWSMEDIA);
#endif
#ifdef NDPI_CONTENT_REALMEDIA
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_CONTENT_REALMEDIA);
#endif
#ifdef NDPI_CONTENT_AVI
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_CONTENT_AVI);
#endif
#ifdef NDPI_CONTENT_OGG
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_CONTENT_OGG);
#endif
#ifdef NDPI_PROTOCOL_MOVE
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MOVE);
#endif
#ifdef NDPI_PROTOCOL_XBOX
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_XBOX);
#endif
}

void _org_ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  u_int16_t filename_start;

  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "search http\n");

  /* set client-server_direction */
  if(flow->l4.tcp.http_setup_dir == 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "initializes http to stage: 1 \n");
    flow->l4.tcp.http_setup_dir = 1 + packet->packet_direction;
  }

  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK
     (ndpi_struct->generic_http_packet_bitmask, packet->detected_protocol_stack[0]) != 0) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	     "protocol might be detected earlier as http jump to payload type detection\n");
    goto http_parse_detection;
  }

  if(flow->l4.tcp.http_setup_dir == 1 + packet->packet_direction) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "http stage: 1\n");

    if(flow->l4.tcp.http_wait_for_retransmission) {
      if(!packet->tcp_retransmission) {
	if(flow->packet_counter <= 5) {
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "still waiting for retransmission\n");
	  return;
	} else {
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "retransmission not found, exclude\n");
	  http_bitmask_exclude(flow);
	  return;
	}
      }
    }

    if(flow->l4.tcp.http_stage == 0) {
      filename_start = http_request_url_offset(ndpi_struct, flow);
      if(filename_start == 0) {
	if(packet->payload_packet_len >= 7 && memcmp(packet->payload, "HTTP/1.", 7) == 0) {
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP response found (truncated flow ?)\n");
	  ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
	  return;
	}

	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "filename not found, exclude\n");
	http_bitmask_exclude(flow);
	return;
      }
      // parse packet
      ndpi_parse_packet_line_info(ndpi_struct, flow);

      if(packet->parsed_lines <= 1) {
	/* parse one more packet .. */
	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "just one line, search next packet\n");

	packet->http_method.ptr = packet->line[0].ptr;
        packet->http_method.len = filename_start - 1;
	flow->l4.tcp.http_stage = 1;
	return;
      }
      // parsed_lines > 1 here
      if(packet->line[0].len >= (9 + filename_start)
	 && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
	u_int16_t proto_id;

	packet->http_url_name.ptr = &packet->payload[filename_start];
	packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

	packet->http_method.ptr = packet->line[0].ptr;
	packet->http_method.len = filename_start - 1;

	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "http structure detected, adding\n");

	if(filename_start == 8 && (memcmp(packet->payload, "CONNECT ", 8) == 0)) /* nathan@getoffmalawn.com */
	  proto_id = NDPI_PROTOCOL_HTTP_CONNECT;
	else {
	  if((packet->http_url_name.len > 7) && (!strncmp((const char*)packet->http_url_name.ptr, "http://", 7)))
	    proto_id = NDPI_PROTOCOL_HTTP_PROXY;
	  else {
	    proto_id = NDPI_PROTOCOL_HTTP;
	  }
	}

	ndpi_int_http_add_connection(ndpi_struct, flow, proto_id);
	check_content_type_and_change_protocol(ndpi_struct, flow);
	/* HTTP found, look for host... */
	if(packet->host_line.ptr != NULL) {
	  /* aaahh, skip this direction and wait for a server reply here */
	  flow->l4.tcp.http_stage = 2;
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP START HOST found\n");
	  return;
	}
	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP START HOST found\n");

	/* host not found, check in next packet after */
	flow->l4.tcp.http_stage = 1;
	return;
      }
    } else if(flow->l4.tcp.http_stage == 1) {
      /* SECOND PAYLOAD TRAFFIC FROM CLIENT, FIRST PACKET MIGHT HAVE BEEN HTTP... */
      /* UNKNOWN TRAFFIC, HERE FOR HTTP again.. */
      // parse packet
      ndpi_parse_packet_line_info(ndpi_struct, flow);

      if(packet->parsed_lines <= 1) {
	/* wait some packets in case request is split over more than 2 packets */
	if(flow->packet_counter < 5) {
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		   "line still not finished, search next packet\n");
	  return;
	} else {
	  /* stop parsing here */
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		   "HTTP: PACKET DOES NOT HAVE A LINE STRUCTURE\n");
	  http_bitmask_exclude(flow);
	  return;
	}
      }
      // http://www.slideshare.net/DSPIP/rtsp-analysis-wireshark
      if(packet->line[0].len >= 9 && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
	check_content_type_and_change_protocol(ndpi_struct, flow);
	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		 "HTTP START HTTP found in 2. packet, check host here...\n");
	/* HTTP found, look for host... */
	flow->l4.tcp.http_stage = 2;

	return;
      }
    }
  } else {
    /* We have received a response for a previously identified partial HTTP request */

    if((packet->parsed_lines == 1) && (packet->packet_direction == 1 /* server -> client */)) {
      /*
	In apache if you do "GET /\n\n" the response comes without any header so we can assume that
	this can be the case
      */
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
      return;
    }

  }

  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: REQUEST NOT HTTP CONFORM\n");
  http_bitmask_exclude(flow);
  return;

 http_parse_detection:
  if(flow->l4.tcp.http_setup_dir == 1 + packet->packet_direction) {
    /* we have something like http here, so check for host and content type if possible */
    if(flow->l4.tcp.http_stage == 0 || flow->l4.tcp.http_stage == 3) {
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP RUN MAYBE NEXT GET/POST...\n");
      // parse packet
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      /* check for url here */
      filename_start = http_request_url_offset(ndpi_struct, flow);
      if(filename_start != 0 && packet->parsed_lines > 1 && packet->line[0].len >= (9 + filename_start)
	 && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
	packet->http_url_name.ptr = &packet->payload[filename_start];
	packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

	packet->http_method.ptr = packet->line[0].ptr;
	packet->http_method.len = filename_start - 1;

	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "next http action, "
		 "resetting to http and search for other protocols later.\n");
	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
      }
      check_content_type_and_change_protocol(ndpi_struct, flow);
      /* HTTP found, look for host... */
      if(packet->host_line.ptr != NULL) {
	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		 "HTTP RUN MAYBE NEXT HOST found, skipping all packets from this direction\n");
	/* aaahh, skip this direction and wait for a server reply here */
	flow->l4.tcp.http_stage = 2;
	return;
      }
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	       "HTTP RUN MAYBE NEXT HOST NOT found, scanning one more packet from this direction\n");
      flow->l4.tcp.http_stage = 1;
    } else if(flow->l4.tcp.http_stage == 1) {
      // parse packet and maybe find a packet info with host ptr,...
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      check_content_type_and_change_protocol(ndpi_struct, flow);
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP RUN second packet scanned\n");
      /* HTTP found, look for host... */
      flow->l4.tcp.http_stage = 2;
    }
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	     "HTTP skipping client packets after second packet\n");
    return;
  }
  /* server response */
  if(flow->l4.tcp.http_stage > 0) {
    /* first packet from server direction, might have a content line */
    ndpi_parse_packet_line_info(ndpi_struct, flow);
    check_content_type_and_change_protocol(ndpi_struct, flow);

    if(packet->empty_line_position_set != 0 || flow->l4.tcp.http_empty_line_seen == 1) {
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "empty line. check_http_payload.\n");
      check_http_payload(ndpi_struct, flow);
    }

    if(flow->l4.tcp.http_stage == 2) {
      flow->l4.tcp.http_stage = 3;
    } else {
      flow->l4.tcp.http_stage = 0;
    }
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	     "HTTP response first or second packet scanned,new stage is: %u\n", flow->l4.tcp.http_stage);
    return;
  } else {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP response next packet skipped\n");
  }
}

/*************************************************************************************************/

static void ndpi_check_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t filename_start;

  /* Check if we so far detected the protocol in the request or not. */
  if (flow->l4.tcp.http_stage == 0) {
    flow->http_detected = 0;

    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP stage %d: \n",
	     flow->l4.tcp.http_stage);

    filename_start = http_request_url_offset(ndpi_struct, flow);


    if (filename_start == 0) {
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	       "Filename HTTP not found, we look for possible truncate flow...\n");
      if (packet->payload_packet_len >= 7 && memcmp(packet->payload, "HTTP/1.", 7) == 0) {
        NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		 "HTTP response found (truncated flow ?)\n");
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
        check_content_type_and_change_protocol(ndpi_struct, flow);
        return;
      }

      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "Exclude HTTP\n");
      http_bitmask_exclude(flow);
      return;
    }

    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	     "Filename HTTP found: %d, we look for line info..\n", filename_start);

    ndpi_parse_packet_line_info(ndpi_struct, flow);

    if (packet->parsed_lines <= 1) {
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	       "Found just one line, we will look further for the next packet...\n");

      packet->http_method.ptr = packet->line[0].ptr;
      packet->http_method.len = filename_start - 1;

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
      return;
    }

    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	     "Found more than one line, we look further for the next packet...\n");

    if(packet->line[0].len >= (9 + filename_start)
        && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {

      packet->http_url_name.ptr = &packet->payload[filename_start];
      packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

      packet->http_method.ptr = packet->line[0].ptr;
      packet->http_method.len = filename_start - 1;

      if((packet->http_url_name.len > 7)
          && (!strncmp((const char*) packet->http_url_name.ptr, "http://", 7))) {
        NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP_PROXY Found.\n");
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP_PROXY);
        check_content_type_and_change_protocol(ndpi_struct, flow);
      }

      if(filename_start == 8 && (memcmp(packet->payload, "CONNECT ", 8) == 0)) /* nathan@getoffmalawn.com */
      {
        NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP_CONNECT Found.\n");
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP_CONNECT);
        check_content_type_and_change_protocol(ndpi_struct, flow);
      }

      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
          "HTTP START Found, we will look for sub-protocols (content and host)...\n");

      check_content_type_and_change_protocol(ndpi_struct, flow);

      if(packet->host_line.ptr != NULL) {
	/*
	  nDPI is pretty scrupoulous about HTTP so it waits until the
	  HTTP response is received just to check that it conforms
	  with the HTTP specs. However this might be a waste of time as
	  in 99.99% of the cases is like that.
	*/

	if(!ndpi_struct->http_dissect_response) {
	  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) /* No subprotocol found */
	    ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
	} else {
	  flow->http_detected = 1;
	  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		   "HTTP START Found, we will look further for the response...\n");
	  flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
	}

	return;
      }
    }

    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: REQUEST NOT HTTP CONFORM\n");
    http_bitmask_exclude(flow);
  } else if ((flow->l4.tcp.http_stage == 1) || (flow->l4.tcp.http_stage == 2)) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP stage %u: \n",
	     flow->l4.tcp.http_stage);

    /* At first check, if this is for sure a response packet (in another direction. If not, if http is detected do nothing now and return,
     * otherwise check the second packet for the http request . */
    if ((flow->l4.tcp.http_stage - packet->packet_direction) == 1) {

      if (flow->http_detected)
        return;

      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
	       " SECOND PAYLOAD TRAFFIC FROM CLIENT, FIRST PACKET MIGHT HAVE BEEN HTTP...UNKNOWN TRAFFIC, HERE FOR HTTP again.. \n");

      ndpi_parse_packet_line_info(ndpi_struct, flow);

      if (packet->parsed_lines <= 1) {
        /* wait some packets in case request is split over more than 2 packets */
        if (flow->packet_counter < 5) {
          NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		   "line still not finished, search next packet\n");
          return;
        } else {
          /* stop parsing here */
          NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		   "HTTP: PACKET DOES NOT HAVE A LINE STRUCTURE\n");
          http_bitmask_exclude(flow);
          return;
        }
      }
      // http://www.slideshare.net/DSPIP/rtsp-analysis-wireshark
      if (packet->line[0].len >= 9
          && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {

        NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "Found HTTP.\n");
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
        check_content_type_and_change_protocol(ndpi_struct, flow);

        NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG,
		 "HTTP START Found in 2. packet, we will look further for the response....\n");
        flow->http_detected = 1;
      }
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    /* We have received a response for a previously identified partial HTTP request */

    if ((packet->parsed_lines == 1) && (packet->packet_direction == 1 /* server -> client */)) {
      /*
	In apache if you do "GET /\n\n" the response comes without any header so we can assume that
	this can be the case
      */
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "Found HTTP. (apache)\n");
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
      check_content_type_and_change_protocol(ndpi_struct, flow);
      return;
    }

    /* If we already detected the http request, we can add the connection and then check for the sub-protocol*/
    if (flow->http_detected)
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);

    /* Parse packet line and we look for the subprotocols */
    ndpi_parse_packet_line_info(ndpi_struct, flow);
    check_content_type_and_change_protocol(ndpi_struct, flow);

    if (packet->empty_line_position_set != 0 || flow->l4.tcp.http_empty_line_seen == 1) {
      NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "empty line. check_http_payload.\n");
      check_http_payload(ndpi_struct, flow);
    }

    flow->l4.tcp.http_stage = 0;
    return;
  }

}

void ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "Exclude HTTP.\n");
    http_bitmask_exclude(flow);
    return;
  }

  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
     return;
   }

  NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "HTTP detection...\n");
  ndpi_check_http_tcp(ndpi_struct, flow);
}

/* ********************************* */

ndpi_http_method ndpi_get_http_method(struct ndpi_detection_module_struct *ndpi_mod,
				      struct ndpi_flow_struct *flow) {
  if(!flow)
    return(HTTP_METHOD_UNKNOWN);
  else
    return(flow->http.method);
}

/* ********************************* */

char* ndpi_get_http_url(struct ndpi_detection_module_struct *ndpi_mod,
			struct ndpi_flow_struct *flow) {
  if((!flow) || (!flow->http.url))
    return("");
  else
    return(flow->http.url);
}

/* ********************************* */

char* ndpi_get_http_content_type(struct ndpi_detection_module_struct *ndpi_mod,
			       struct ndpi_flow_struct *flow) {
  if((!flow) || (!flow->http.content_type))
    return("");
  else
    return(flow->http.content_type);
}

#endif
