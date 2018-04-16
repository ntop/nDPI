/*
 * http.c
 *
 * Copyright (C) 2011-17 - ntop.org
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

#ifdef NDPI_PROTOCOL_HTTP

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HTTP

#include "ndpi_api.h"


/* global variables used for 1kxun protocol and iqiyi service */

static void ndpi_int_http_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow,
					 u_int32_t protocol) {

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
    /* This is HTTP and it is not a sub protocol (e.g. skype or dropbox) */

    ndpi_search_tcp_or_udp(ndpi_struct, flow);

    /* If no custom protocol has been detected */
    /* if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) */
    if(protocol == NDPI_PROTOCOL_HTTP) {
      ndpi_int_reset_protocol(flow);
      ndpi_set_detected_protocol(ndpi_struct, flow, flow->guessed_host_protocol_id, protocol);
    } else
      ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_HTTP);
    
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

    NDPI_LOG_INFO(ndpi_struct, "found Flash content in HTTP\n");
    ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_CONTENT_FLASH);
  }
}
#endif

#ifdef NDPI_CONTENT_AVI
static void avi_check_http_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;


  NDPI_LOG_DBG2(ndpi_struct, "called avi_check_http_payload: %u %u %u\n",
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
      NDPI_LOG_INFO(ndpi_struct, "found Avi content in HTTP\n");
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_CONTENT_AVI);
    }
    flow->l4.tcp.http_empty_line_seen = 0;
    return;
  }

  /**
     for reference see http://msdn.microsoft.com/archive/default.asp?url=/archive/en-us/directx9_c/directx/htm/avirifffilereference.asp
  **/
  if(packet->empty_line_position_set != 0) {

    u_int32_t p = packet->empty_line_position + 2;

    // check for avi header
    NDPI_LOG_DBG2(ndpi_struct, "p = %u\n", p);

    if((p + 16) <= packet->payload_packet_len && memcmp(&packet->payload[p], "RIFF", 4) == 0
       && memcmp(&packet->payload[p + 8], "AVI LIST", 8) == 0) {
      NDPI_LOG_INFO(ndpi_struct, "found Avi content in HTTP\n");
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

  NDPI_LOG_DBG2(ndpi_struct, "called teamviewer_check_http_payload: %u %u %u\n",
	   packet->empty_line_position_set, flow->l4.tcp.http_empty_line_seen, packet->empty_line_position);

  if(packet->empty_line_position_set == 0 || (packet->empty_line_position + 5) > (packet->payload_packet_len))
    return;

  pos = &packet->payload[packet->empty_line_position] + 2;

  if(pos[0] == 0x17 && pos[1] == 0x24) {
    NDPI_LOG_INFO(ndpi_struct, "found TeamViewer content in HTTP\n");
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
    NDPI_LOG_INFO(ndpi_struct, "found RTSP accept line\n");
    ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RTSP);
  }
}
#endif

static void setHttpUserAgent(struct ndpi_flow_struct *flow, char *ua) {
  if (    !strcmp(ua, "Windows NT 5.0"))  ua = "Windows 2000";
  else if(!strcmp(ua, "Windows NT 5.1"))  ua = "Windows XP";
  else if(!strcmp(ua, "Windows NT 5.2"))  ua = "Windows Server 2003";
  else if(!strcmp(ua, "Windows NT 6.0"))  ua = "Windows Vista";
  else if(!strcmp(ua, "Windows NT 6.1"))  ua = "Windows 7";
  else if(!strcmp(ua, "Windows NT 6.2"))  ua = "Windows 8";
  else if(!strcmp(ua, "Windows NT 6.3"))  ua = "Windows 8.1";
  else if(!strcmp(ua, "Windows NT 10.0")) ua = "Windows 10";

  /* Good reference for future implementations:
   * https://github.com/ua-parser/uap-core/blob/master/regexes.yaml */

  //printf("==> %s\n", ua);
  snprintf((char*)flow->protos.http.detected_os, sizeof(flow->protos.http.detected_os), "%s", ua);
}

static void parseHttpSubprotocol(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  if((flow->l4.tcp.http_stage == 0) || (flow->http.url && flow->http_detected)) {
      char *double_col = strchr((char*)flow->host_server_name, ':');

      if(double_col) double_col[0] = '\0';

    /**
       NOTE
       If http_dont_dissect_response = 1 dissection of HTTP response
       mime types won't happen
    */
    ndpi_match_host_subprotocol(ndpi_struct, flow, (char *)flow->host_server_name,
				strlen((const char *)flow->host_server_name),
				NDPI_PROTOCOL_HTTP);
  }
}

/**
   NOTE
   ndpi_parse_packet_line_info is in ndpi_main.c
*/
static void check_content_type_and_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						   struct ndpi_flow_struct *flow) {

  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t a;


#if defined(NDPI_PROTOCOL_1KXUN) || defined(NDPI_PROTOCOL_IQIYI)
  /* PPStream */
  if(flow->l4.tcp.ppstream_stage > 0 && flow->iqiyi_counter == 0) {
    NDPI_LOG_INFO(ndpi_struct, "found PPStream\n");
    /* ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_PPSTREAM); */
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PPSTREAM, NDPI_PROTOCOL_HTTP);
  }
  else if(flow->iqiyi_counter > 0) {
    NDPI_LOG_INFO(ndpi_struct, "found iQiyi\n");
    /* ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_IQIYI); */
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_IQIYI, NDPI_PROTOCOL_HTTP);
  }
#endif

#if defined(NDPI_PROTOCOL_1KXUN) || defined(NDPI_PROTOCOL_IQIYI)
  /* 1KXUN */
  if(flow->kxun_counter > 0) {
    NDPI_LOG_INFO(ndpi_struct, "found 1kxun\n");
    /* ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_1KXUN); */
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_1KXUN, NDPI_PROTOCOL_HTTP);
  }
#endif

  if(!ndpi_struct->http_dont_dissect_response) {
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
    /**
       Format examples:
         Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) ....
         Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0
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
      else if(memcmp(ua, "netflix-ios-app", 15) == 0) {
	NDPI_LOG_INFO(ndpi_struct, "found netflix\n");
      	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_NETFLIX);
      	return;
      }
    }

    NDPI_LOG_DBG2(ndpi_struct, "User Agent Type line found %.*s\n",
	     packet->user_agent_line.len, packet->user_agent_line.ptr);
  }

  /* check for host line */
  if(packet->host_line.ptr != NULL) {
    u_int len;

    NDPI_LOG_DBG2(ndpi_struct, "HOST line found %.*s\n",
	     packet->host_line.len, packet->host_line.ptr);

    /* call ndpi_match_host_subprotocol to see if there is a match with known-host HTTP subprotocol */
    if((ndpi_struct->http_dont_dissect_response) || flow->http_detected)
      ndpi_match_host_subprotocol(ndpi_struct, flow,
				  (char*)packet->host_line.ptr,
				  packet->host_line.len,
				  NDPI_PROTOCOL_HTTP);

    /* Copy result for nDPI apps */
    len = ndpi_min(packet->host_line.len, sizeof(flow->host_server_name)-1);
    strncpy((char*)flow->host_server_name, (char*)packet->host_line.ptr, len);
    flow->host_server_name[len] = '\0', flow->server_id = flow->dst;

    if(packet->forwarded_line.ptr) {
        len = ndpi_min(packet->forwarded_line.len, sizeof(flow->protos.http.nat_ip)-1);
        strncpy((char*)flow->protos.http.nat_ip, (char*)packet->forwarded_line.ptr, len);
        flow->protos.http.nat_ip[len] = '\0';
    }

    if(ndpi_struct->http_dont_dissect_response)
      parseHttpSubprotocol(ndpi_struct, flow);

    /**
       check result of host subprotocol detection

       if "detected" in flow == 0 then "detected" = "guess"
       else "guess" = "detected"
    **/
    if(flow->detected_protocol_stack[1] == 0) {
      flow->detected_protocol_stack[1] = flow->guessed_protocol_id;
      if(flow->detected_protocol_stack[0] == 0)
    	flow->detected_protocol_stack[0] = flow->guessed_host_protocol_id;
    }
    else {
      if(flow->detected_protocol_stack[1] != flow->guessed_protocol_id)
	flow->guessed_protocol_id = flow->detected_protocol_stack[1];
      if(flow->detected_protocol_stack[0] != flow->guessed_host_protocol_id)
	flow->guessed_host_protocol_id = flow->detected_protocol_stack[0];
    }

    if((flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
       && ((ndpi_struct->http_dont_dissect_response) || flow->http_detected)
       && (packet->http_origin.len > 0))
      ndpi_match_host_subprotocol(ndpi_struct, flow,
				  (char *)packet->http_origin.ptr,
				  packet->http_origin.len,
				  NDPI_PROTOCOL_HTTP);

    if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
      if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
	NDPI_LOG_INFO(ndpi_struct, "found HTTP/%s\n", 
		    ndpi_get_proto_name(ndpi_struct, packet->detected_protocol_stack[0]));
	ndpi_int_http_add_connection(ndpi_struct, flow, packet->detected_protocol_stack[0]);
	return; /* We have identified a sub-protocol so we're done */
      }
    }
  }

  if(!ndpi_struct->http_dont_dissect_response && flow->http_detected)
    parseHttpSubprotocol(ndpi_struct, flow);

  if(flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN)
    flow->guessed_protocol_id = NDPI_PROTOCOL_HTTP;

  /* check for accept line */
  if(packet->accept_line.ptr != NULL) {
    NDPI_LOG_DBG2(ndpi_struct, "Accept line found %.*s\n",
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
      NDPI_LOG_INFO(ndpi_struct, "found MPEG: Icy-MetaData\n");
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_CONTENT_MPEG);
      return;
    }
  }
#ifdef NDPI_CONTENT_AVI
#endif
#endif

  if(packet->content_line.ptr != NULL && packet->content_line.len != 0) {
    NDPI_LOG_DBG2(ndpi_struct, "Content Type line found %.*s\n",
	     packet->content_line.len, packet->content_line.ptr);

    if((ndpi_struct->http_dont_dissect_response) || flow->http_detected)
      ndpi_match_content_subprotocol(ndpi_struct, flow,
				     (char*)packet->content_line.ptr, packet->content_line.len,
				     NDPI_PROTOCOL_HTTP);
  }
}

static void check_http_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_DBG2(ndpi_struct, "called check_http_payload\n");

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
 * Functions to check whether the packet begins with a valid http request
 * @param ndpi_struct
 * @returnvalue 0 if no valid request has been found
 * @returnvalue >0 indicates start of filename but not necessarily in packet limit
 */

#define STATIC_STRING_L(a) {.str=a, .len=sizeof(a)-1 }

static struct l_string {
	const char *str;
	size_t     len;
} http_methods[] = {
	STATIC_STRING_L("GET "),
	STATIC_STRING_L("POST "),
	STATIC_STRING_L("OPTIONS "),
	STATIC_STRING_L("HEAD "),
	STATIC_STRING_L("PUT "),
	STATIC_STRING_L("DELETE "),
	STATIC_STRING_L("CONNECT "),
	STATIC_STRING_L("PROPFIND "),
	STATIC_STRING_L("REPORT ") };
static const char *http_fs = "CDGHOPR";

static uint8_t non_ctrl(uint8_t c) {
	return c < 32 ? '.':c;
}

static u_int16_t http_request_url_offset(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  int i;

  NDPI_LOG_DBG2(ndpi_struct, "====>>>> HTTP: %c%c%c%c [len: %u]\n",
	   non_ctrl(packet->payload[0]), non_ctrl(packet->payload[1]),
	   non_ctrl(packet->payload[2]), non_ctrl(packet->payload[3]),
	   packet->payload_packet_len);

  /* Check first char */
  if(!strchr(http_fs,packet->payload[0])) return 0;
  /**
     FIRST PAYLOAD PACKET FROM CLIENT
  **/
  for(i=0; i < sizeof(http_methods)/sizeof(http_methods[0]); i++) {
	if(packet->payload_packet_len >= http_methods[i].len &&
	   memcmp(packet->payload,http_methods[i].str,http_methods[i].len) == 0) {
		NDPI_LOG_DBG2(ndpi_struct, "HTTP: %sFOUND\n",http_methods[i].str);
		return http_methods[i].len;
	}
  }
  return 0;
}

static void http_bitmask_exclude_other(struct ndpi_flow_struct *flow)
{
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
#ifdef NDPI_PROTOCOL_XBOX
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_XBOX);
#endif
}

/*************************************************************************************************/

static void ndpi_check_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {       
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t filename_start; /* the filename in the request method line, e.g., "GET filename_start..."*/

  packet->packet_lines_parsed_complete = 0;

  /* Check if we so far detected the protocol in the request or not. */
  if(flow->l4.tcp.http_stage == 0) {
    /* Expected a request */
    flow->http_detected = 0;

    NDPI_LOG_DBG2(ndpi_struct, "HTTP stage %d: \n", flow->l4.tcp.http_stage);

    filename_start = http_request_url_offset(ndpi_struct, flow);

    if(filename_start == 0) { /* not a regular request. In the HTTP first stage, may be a truncated flow or other protocols */
      NDPI_LOG_DBG2(ndpi_struct, "Filename HTTP not found, we look for possible truncate flow..\n");

      if(packet->payload_packet_len >= 7 && memcmp(packet->payload, "HTTP/1.", 7) == 0) {
        NDPI_LOG_INFO(ndpi_struct, "found HTTP response\n");
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
        check_content_type_and_change_protocol(ndpi_struct, flow);
        return;
      }

      if((packet->payload_packet_len == 3) && memcmp(packet->payload, "HI\n", 3) == 0) {
	/* This looks like Ookla: we don't give up with HTTP yet */
        flow->l4.tcp.http_stage = 1;
	return;
      }
      
      if((packet->payload_packet_len == 40) && (flow->l4.tcp.http_stage == 0)) {
        /*
	  -> QR O06L0072-6L91-4O43-857J-K8OO172L6L51
	  <- QNUUX 2.5 2017-08-15.1314.4jn12m5
	  -> MXFWUXJM 31625365
	*/

        if((packet->payload[2] == ' ')
	   && (packet->payload[11] == '-')
	   && (packet->payload[16] == '-')
	   && (packet->payload[21] == '-')
	   && (packet->payload[26] == '-')
	   && (packet->payload[39] == 0x0A)
		)
		flow->l4.tcp.http_stage = 1;
	return;	      
      }
      
      if((packet->payload_packet_len == 23) && (memcmp(packet->payload, "<policy-file-request/>", 23) == 0)) {
        /*
          <policy-file-request/>
          <cross-domain-policy>
          <allow-access-from domain="*.ookla.com" to-ports="8080"/>
          <allow-access-from domain="*.speedtest.net" to-ports="8080"/>
          </cross-domain-policy>
        */
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_UNKNOWN);
        return;
      }
      
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      http_bitmask_exclude_other(flow);
      return;
    }

    NDPI_LOG_DBG2(ndpi_struct,
	     "Filename HTTP found: %d, we look for line info..\n", filename_start);

    ndpi_parse_packet_line_info(ndpi_struct, flow);

    if(packet->parsed_lines <= 1) {
      NDPI_LOG_DBG2(ndpi_struct,
	       "Found just one line, we will look further for the next packet...\n");

      packet->http_method.ptr = packet->line[0].ptr;
      packet->http_method.len = filename_start - 1;

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
      return;
    }

    NDPI_LOG_DBG2(ndpi_struct,
	     "Found more than one line, we look further for the next packet...\n");

    if(packet->line[0].len >= (9 + filename_start)
        && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) { /* Request line complete. Ex. "GET / HTTP/1.1" */

      packet->http_url_name.ptr = &packet->payload[filename_start];
      packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

      packet->http_method.ptr = packet->line[0].ptr;
      packet->http_method.len = filename_start - 1;

      // Set the HTTP requested version: 0=HTTP/1.0 and 1=HTTP/1.1
      if(memcmp(&packet->line[0].ptr[packet->line[0].len - 1], "1", 1) == 0)
          flow->http.request_version = 1;
      else
          flow->http.request_version = 0;

      /* Set the first found headers in request */
      flow->http.num_request_headers = packet->http_num_headers;


      /* Check for Ookla */
      if((packet->referer_line.len > 0)
	      && ndpi_strnstr((const char *)packet->referer_line.ptr, "www.speedtest.net", packet->referer_line.len)) {
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_HTTP);
	    return;
      }

      /* Check for additional field introduced by Steam */
      int x = 1;
      if(packet->line[x].len >= 11 && (memcmp(packet->line[x].ptr, "x-steam-sid", 11)) == 0) {
	    NDPI_LOG_INFO(ndpi_struct, "found STEAM\n");
	    ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_STEAM);
	    check_content_type_and_change_protocol(ndpi_struct, flow);
	    return;
      }

      /* Check for additional field introduced by Facebook */
      x = 1;
      while(packet->line[x].len != 0) {
	    if(packet->line[x].len >= 12 && (memcmp(packet->line[x].ptr, "X-FB-SIM-HNI", 12)) == 0) {
	      NDPI_LOG_INFO(ndpi_struct, "found FACEBOOK\n");
	      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FACEBOOK);
	      check_content_type_and_change_protocol(ndpi_struct, flow);
	      return;
	    }
	    x++;
      }

#if defined(NDPI_PROTOCOL_1KXUN) || defined(NDPI_PROTOCOL_IQIYI)
      /* check PPStream protocol or iQiyi service
	 (iqiyi is delivered by ppstream) */
      // substring in url
      if(ndpi_strnstr((const char*) &packet->payload[filename_start], "iqiyi.com", (packet->payload_packet_len - filename_start)) != NULL) {
	if(flow->kxun_counter == 0) {
	  flow->l4.tcp.ppstream_stage++;
	  flow->iqiyi_counter++;
	  check_content_type_and_change_protocol(ndpi_struct, flow); /* ***** CHECK ****** */
	  return;
	}
      }

      // additional field in http payload
      x = 1;
      while((packet->line[x].len >= 4) && (packet->line[x+1].len >= 5) && (packet->line[x+2].len >= 10)) {
	if(packet->line[x].ptr && ((memcmp(packet->line[x].ptr, "qyid", 4)) == 0)
	   && packet->line[x+1].ptr && ((memcmp(packet->line[x+1].ptr, "qypid", 5)) == 0)
	   && packet->line[x+2].ptr && ((memcmp(packet->line[x+2].ptr, "qyplatform", 10)) == 0)
	   ) {
	  flow->l4.tcp.ppstream_stage++;
	  flow->iqiyi_counter++;
	  check_content_type_and_change_protocol(ndpi_struct, flow);
	  return;
	}
	x++;
      }
#endif

#if defined(NDPI_PROTOCOL_1KXUN) || defined(NDPI_PROTOCOL_IQIYI)
      /* Check for 1kxun packet */
      int a;
      for (a = 0; a < packet->parsed_lines; a++) {
	if(packet->line[a].len >= 14 && (memcmp(packet->line[a].ptr, "Client-Source:", 14)) == 0) {
	  if((memcmp(packet->line[a].ptr+15, "1kxun", 5)) == 0) {
	    flow->kxun_counter++;
	    check_content_type_and_change_protocol(ndpi_struct, flow);
	    return;
	  }
	}
      }
#endif
      
      if((packet->http_url_name.len > 7)
          && (!strncmp((const char*) packet->http_url_name.ptr, "http://", 7))) {
        NDPI_LOG_INFO(ndpi_struct, "found HTTP_PROXY\n");
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP_PROXY);
        check_content_type_and_change_protocol(ndpi_struct, flow);
      }

      if(filename_start == 8 && (memcmp(packet->payload, "CONNECT ", 8) == 0)) {
	    /* nathan@getoffmalawn.com */
        NDPI_LOG_INFO(ndpi_struct, "found HTTP_CONNECT\n");
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP_CONNECT);
        check_content_type_and_change_protocol(ndpi_struct, flow);
      }

      NDPI_LOG_DBG2(ndpi_struct,
          "HTTP START Found, we will look for sub-protocols (content and host)...\n");

      if(packet->host_line.ptr != NULL) {
        /**
           nDPI is pretty scrupulous about HTTP so it waits until the
           HTTP response is received just to check that it conforms
           with the HTTP specs. However this might be a waste of time as
           in 99.99% of the cases is like that.
        */

        if(ndpi_struct->http_dont_dissect_response) {
          if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) /* No subprotocol found */
	    NDPI_LOG_INFO(ndpi_struct, "found HTTP\n");
            ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
        } else {
          flow->http_detected = 1;
          NDPI_LOG_DBG2(ndpi_struct,
               "HTTP START Found, we will look further for the response...\n");
          flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
        }

        check_content_type_and_change_protocol(ndpi_struct, flow);
        return;
      }
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    http_bitmask_exclude_other(flow);

  } else if((flow->l4.tcp.http_stage == 1) || (flow->l4.tcp.http_stage == 2)) {

    NDPI_LOG_DBG2(ndpi_struct, "HTTP stage %u: \n", flow->l4.tcp.http_stage);
    
    if((packet->payload_packet_len == 34) && (flow->l4.tcp.http_stage == 1)) {
      if((packet->payload[5] == ' ') && (packet->payload[9] == ' ')) {
	      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA);
	      return;
      }
    }
    
    if((packet->payload_packet_len > 6) && memcmp(packet->payload, "HELLO ", 6) == 0) {
       /* This looks like Ookla */
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_UNKNOWN);
      return;
    } else
	    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_OOKLA);    
    
    /**
       At first check, if this is for sure a response packet (in another direction. If not, if HTTP is detected do nothing now and return,
       otherwise check the second packet for the HTTP request
    */
    if((flow->l4.tcp.http_stage - packet->packet_direction) == 1) { /* Expected a response package */

      if(flow->http_detected)
        return;

      NDPI_LOG_DBG2(ndpi_struct,
	       " SECOND PAYLOAD TRAFFIC FROM CLIENT, FIRST PACKET MIGHT HAVE BEEN HTTP...UNKNOWN TRAFFIC, HERE FOR HTTP again.. \n");

      ndpi_parse_packet_line_info(ndpi_struct, flow);

      // Add more found HTTP request headers.
      flow->http.num_request_headers+=packet->http_num_headers;

      if(packet->parsed_lines <= 1) {
        /* wait some packets in case request is split over more than 2 packets */
        if(flow->packet_counter < 5) {
          NDPI_LOG_DBG2(ndpi_struct, "line still not finished, search next packet\n");
          return;
        } else {
          /* stop parsing here */
          NDPI_LOG_DBG2(ndpi_struct, "exclude HTTP: PACKET DOES NOT HAVE A LINE STRUCTURE\n");
	  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          http_bitmask_exclude_other(flow);
          return;
        }
      }
      // http://www.slideshare.net/DSPIP/rtsp-analysis-wireshark
      if(packet->line[0].len >= 9
          && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {

        NDPI_LOG_INFO(ndpi_struct, "found HTTP\n");
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
        check_content_type_and_change_protocol(ndpi_struct, flow);

        NDPI_LOG_DBG2(ndpi_struct,
		 "HTTP START Found in 2. packet, we will look further for the response....\n");
        flow->http_detected = 1;
      }

      return;
    }

    /**
       This is a packet in another direction. Check if we find the proper response.
       We have received a response for a previously identified partial HTTP request
    */

    /* response without headers
     * TODO: Shouldn't it be below  ndpi_parse_packet_line_info, line ~825 ?
     */
    if((packet->parsed_lines == 1) && (packet->packet_direction == 1 /* server -> client */)) {
      /* In Apache if you do "GET /\n\n" the response comes without any header */
      NDPI_LOG_INFO(ndpi_struct, "found HTTP. (apache)\n");
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
      check_content_type_and_change_protocol(ndpi_struct, flow);
      return;
    }

    /* If we already detected the HTTP request, we can add the connection and then check for the sub-protocol */
    if(flow->http_detected) {
      NDPI_LOG_INFO(ndpi_struct, "found HTTP\n");
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
    }

    /* Parse packet line and we look for the subprotocols */
    ndpi_parse_packet_line_info(ndpi_struct, flow);
    check_content_type_and_change_protocol(ndpi_struct, flow);

    if(packet->packet_direction == 1 /* server -> client */){
        flow->http.num_response_headers += packet->http_num_headers; /* flow structs are initialized with zeros */
    }

    if(packet->empty_line_position_set != 0 || flow->l4.tcp.http_empty_line_seen == 1) {
      NDPI_LOG_DBG2(ndpi_struct, "empty line. check_http_payload\n");
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
  if(flow->packet_counter > 20) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    http_bitmask_exclude_other(flow);
    return;
  }

  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
     return;
   }

  NDPI_LOG_DBG(ndpi_struct, "search HTTP\n");
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


void init_http_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("HTTP",ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_HTTP,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;

#if 0
  ndpi_set_bitmask_protocol_detection("HTTP_Proxy", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_HTTP_PROXY,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;

#ifdef NDPI_CONTENT_MPEG
  ndpi_set_bitmask_protocol_detection("MPEG", ndpi_struct, detection_bitmask, *id,
				      NDPI_CONTENT_MPEG,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
#endif
#ifdef NDPI_CONTENT_FLASH
  ndpi_set_bitmask_protocol_detection("Flash", ndpi_struct, detection_bitmask, *id,
				      NDPI_CONTENT_FLASH,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
#endif
#ifdef NDPI_CONTENT_QUICKTIME
  ndpi_set_bitmask_protocol_detection("QuickTime", ndpi_struct, detection_bitmask, *id,
				      NDPI_CONTENT_QUICKTIME,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
#endif
#ifdef NDPI_CONTENT_REALMEDIA
  ndpi_set_bitmask_protocol_detection("RealMedia", ndpi_struct, detection_bitmask, *id,
				      NDPI_CONTENT_REALMEDIA,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
#endif
#ifdef NDPI_CONTENT_WINDOWSMEDIA
  ndpi_set_bitmask_protocol_detection("WindowsMedia", ndpi_struct, detection_bitmask, *id,
				      NDPI_CONTENT_WINDOWSMEDIA,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
#endif
#ifdef NDPI_CONTENT_MMS
  ndpi_set_bitmask_protocol_detection("MMS", ndpi_struct, detection_bitmask, *id,
				      NDPI_CONTENT_MMS,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
#endif
#ifdef NDPI_PROTOCOL_XBOX
  ndpi_set_bitmask_protocol_detection("Xbox", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_XBOX,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
#endif
#ifdef NDPI_PROTOCOL_QQ
  ndpi_set_bitmask_protocol_detection("QQ", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_QQ,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
#endif
#ifdef NDPI_CONTENT_AVI
  ndpi_set_bitmask_protocol_detection("AVI", ndpi_struct, detection_bitmask, *id,
				      NDPI_CONTENT_AVI,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
#endif
#ifdef NDPI_CONTENT_OGG
  ndpi_set_bitmask_protocol_detection("OggVorbis", ndpi_struct, detection_bitmask, *id,
				      NDPI_CONTENT_OGG,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
#endif

  /* Update excluded protocol bitmask */
  NDPI_BITMASK_SET(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,
  		   ndpi_struct->callback_buffer[a].detection_bitmask);

  /*Delete protocol from excluded protocol bitmask*/
  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask, NDPI_PROTOCOL_UNKNOWN);

  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask, NDPI_PROTOCOL_QQ);

#ifdef NDPI_CONTENT_FLASH
  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask, NDPI_CONTENT_FLASH);
#endif

  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,  NDPI_CONTENT_MMS);

  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask, NDPI_PROTOCOL_XBOX);

  NDPI_BITMASK_SET(ndpi_struct->generic_http_packet_bitmask, ndpi_struct->callback_buffer[a].detection_bitmask);

  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->generic_http_packet_bitmask, NDPI_PROTOCOL_UNKNOWN);

  /* Update callback_buffer index */
  a++;

#endif

}

#endif
