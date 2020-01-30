/*
 * http.c
 *
 * Copyright (C) 2011-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HTTP

#include "ndpi_api.h"
#include <stdlib.h>

static void ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow);

/* *********************************************** */

static int ndpi_search_http_tcp_again(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow) {
  ndpi_search_http_tcp(ndpi_struct, flow);

#ifdef HTTP_DEBUG
  printf("=> %s()\n", __FUNCTION__);
#endif

  if((flow->host_server_name[0] != '\0') && (flow->http.response_status_code != 0)) {
    /* stop extra processing */
    flow->extra_packets_func = NULL; /* We're good now */
    return(0);
  }

  /* Possibly more processing */
  return(1);
}

/* *********************************************** */

/* https://www.freeformatter.com/mime-types-list.html */
static ndpi_protocol_category_t ndpi_http_check_content(struct ndpi_detection_module_struct *ndpi_struct,
							struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->content_line.len > 0) {
    u_int app_len = sizeof("application");

    if(packet->content_line.len > app_len) {
      if(ndpi_strncasestr((const char *)&packet->content_line.ptr[app_len], "mpeg",
			  packet->content_line.len-app_len) != NULL) {
	flow->guessed_category = flow->category = NDPI_PROTOCOL_CATEGORY_STREAMING;
	return(flow->category);
      }
    }

    switch(packet->content_line.ptr[0]) {
    case 'a':
      if(strncasecmp((const char *)packet->content_line.ptr, "audio",
		     ndpi_min(packet->content_line.len, 5)) == 0)
	flow->guessed_category = flow->category = NDPI_PROTOCOL_CATEGORY_MEDIA;
      break;
      
    case 'v':
      if(strncasecmp((const char *)packet->content_line.ptr, "video",
		     ndpi_min(packet->content_line.len, 5)) == 0)
	flow->guessed_category = flow->category = NDPI_PROTOCOL_CATEGORY_MEDIA;
      break;
    }
  }

  return(flow->category);
}

/* *********************************************** */

static void ndpi_int_http_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow,
					 u_int16_t http_protocol,
					 ndpi_protocol_category_t category) {
#ifdef HTTP_DEBUG
  printf("=> %s()\n", __FUNCTION__);
#endif

  if(flow->extra_packets_func && (flow->guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN))
     return; /* Nothing new to add */

  /* This is HTTP and it is not a sub protocol (e.g. skype or dropbox) */
  ndpi_search_tcp_or_udp(ndpi_struct, flow);

  /* If no custom protocol has been detected */
  if((flow->guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN) || (http_protocol != NDPI_PROTOCOL_HTTP))
    flow->guessed_host_protocol_id = http_protocol;

  category = ndpi_http_check_content(ndpi_struct, flow);
  ndpi_int_reset_protocol(flow);
  ndpi_set_detected_protocol(ndpi_struct, flow, flow->guessed_host_protocol_id, NDPI_PROTOCOL_HTTP);

  /* This is necessary to inform the core to call this dissector again */
  flow->check_extra_packets = 1;
  flow->max_extra_packets_to_check = 5;
  flow->extra_packets_func = ndpi_search_http_tcp_again;
  flow->http_detected = 1, flow->guessed_category = flow->category = category;
}

/* ************************************************************* */

static void rtsp_parse_packet_acceptline(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if((packet->accept_line.len >= 28)
     && (memcmp(packet->accept_line.ptr, "application/x-rtsp-tunnelled", 28) == 0)) {
    NDPI_LOG_INFO(ndpi_struct, "found RTSP accept line\n");
    ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RTSP, NDPI_PROTOCOL_CATEGORY_MEDIA);
  }
}

/* ************************************************************* */

static void setHttpUserAgent(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow, char *ua) {
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
  snprintf((char*)flow->protos.http.detected_os,
	   sizeof(flow->protos.http.detected_os), "%s", ua);  
}

/* ************************************************************* */

static void ndpi_http_parse_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  if((flow->l4.tcp.http_stage == 0) || (flow->http.url && flow->http_detected)) {
    char *double_col = strchr((char*)flow->host_server_name, ':');

    if(double_col) double_col[0] = '\0';

    ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HTTP, 
				 (char *)flow->host_server_name,
				 strlen((const char *)flow->host_server_name));
  }
}

/* ************************************************************* */

/**
   NOTE
   ndpi_parse_packet_line_info is in ndpi_main.c
*/
static void check_content_type_and_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HTTP, NDPI_PROTOCOL_UNKNOWN);

  if(flow->http_detected && (flow->http.response_status_code != 0))
    return;

#if defined(NDPI_PROTOCOL_1KXUN) || defined(NDPI_PROTOCOL_IQIYI)
  /* PPStream */
  if(flow->l4.tcp.ppstream_stage > 0 && flow->iqiyi_counter == 0) {
    NDPI_LOG_INFO(ndpi_struct, "found PPStream\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PPSTREAM,
			       NDPI_PROTOCOL_HTTP, NDPI_PROTOCOL_CATEGORY_STREAMING);
  } else if(flow->iqiyi_counter > 0) {
    NDPI_LOG_INFO(ndpi_struct, "found iQiyi\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_IQIYI,
			       NDPI_PROTOCOL_HTTP, NDPI_PROTOCOL_CATEGORY_STREAMING);
  }
#endif

#if defined(NDPI_PROTOCOL_1KXUN) || defined(NDPI_PROTOCOL_IQIYI)
  /* 1KXUN */
  if(flow->kxun_counter > 0) {
    NDPI_LOG_INFO(ndpi_struct, "found 1kxun\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_1KXUN, NDPI_PROTOCOL_CATEGORY_STREAMING);
  }
#endif

    if((flow->http.url == NULL)
       && (packet->http_url_name.len > 0)
       && (packet->host_line.len > 0)) {
      int len = packet->http_url_name.len + packet->host_line.len + 1;

      flow->http.url = ndpi_malloc(len);
      if(flow->http.url) {
	strncpy(flow->http.url, (char*)packet->host_line.ptr, packet->host_line.len);
	strncpy(&flow->http.url[packet->host_line.len], (char*)packet->http_url_name.ptr,
		packet->http_url_name.len);
	flow->http.url[len-1] = '\0';
      }

      if(flow->packet.http_method.len < 3)
        flow->http.method = NDPI_HTTP_METHOD_UNKNOWN;
      else {
        switch(flow->packet.http_method.ptr[0]) {
        case 'O':  flow->http.method = NDPI_HTTP_METHOD_OPTIONS; break;
        case 'G':  flow->http.method = NDPI_HTTP_METHOD_GET; break;
        case 'H':  flow->http.method = NDPI_HTTP_METHOD_HEAD; break;

        case 'P':
          switch(flow->packet.http_method.ptr[1]) {
          case 'A': flow->http.method = NDPI_HTTP_METHOD_PATCH; break;
          case 'O': flow->http.method = NDPI_HTTP_METHOD_POST; break;
          case 'U': flow->http.method = NDPI_HTTP_METHOD_PUT; break;
          }
          break;

        case 'D':   flow->http.method = NDPI_HTTP_METHOD_DELETE; break;
        case 'T':   flow->http.method = NDPI_HTTP_METHOD_TRACE; break;
        case 'C':   flow->http.method = NDPI_HTTP_METHOD_CONNECT; break;
        default:
          flow->http.method = NDPI_HTTP_METHOD_UNKNOWN;
          break;
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
	      setHttpUserAgent(ndpi_struct, flow, token);
	  }
	}
      } else if((packet->user_agent_line.len > 14) && (memcmp(ua, "netflix-ios-app", 15) == 0)) {
	NDPI_LOG_INFO(ndpi_struct, "found netflix\n");
      	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_NETFLIX, NDPI_PROTOCOL_CATEGORY_STREAMING);
      	return;
      }
    }

    if(flow->http.user_agent == NULL) {
      int len = packet->user_agent_line.len + 1;

      flow->http.user_agent = ndpi_malloc(len);
      if(flow->http.user_agent) {
	strncpy(flow->http.user_agent, (char*)packet->user_agent_line.ptr,
		packet->user_agent_line.len);
	flow->http.user_agent[packet->user_agent_line.len] = '\0';
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

    /* Copy result for nDPI apps */
    len = ndpi_min(packet->host_line.len, sizeof(flow->host_server_name)-1);
    strncpy((char*)flow->host_server_name, (char*)packet->host_line.ptr, len);
    flow->host_server_name[len] = '\0';
    flow->extra_packets_func = NULL; /* We're good now */

    flow->server_id = flow->dst;

    if(packet->forwarded_line.ptr) {
      len = ndpi_min(packet->forwarded_line.len, sizeof(flow->protos.http.nat_ip)-1);
      strncpy((char*)flow->protos.http.nat_ip, (char*)packet->forwarded_line.ptr, len);
      flow->protos.http.nat_ip[len] = '\0';
    }

    ndpi_http_parse_subprotocol(ndpi_struct, flow);

    /**
       check result of host subprotocol detection

       if "detected" in flow == 0 then "detected" = "guess"
       else "guess" = "detected"
    **/
    if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
      /* Avoid putting as subprotocol a "core" protocol such as SSL or DNS */
      if(ndpi_struct->proto_defaults[flow->guessed_protocol_id].can_have_a_subprotocol == 0) {
	flow->detected_protocol_stack[1] = flow->guessed_protocol_id;
	if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
	  flow->detected_protocol_stack[0] = flow->guessed_host_protocol_id;
      }
    }
    else {
      if(flow->detected_protocol_stack[1] != flow->guessed_protocol_id)
	flow->guessed_protocol_id = flow->detected_protocol_stack[1];
      if(flow->detected_protocol_stack[0] != flow->guessed_host_protocol_id)
	flow->guessed_host_protocol_id = flow->detected_protocol_stack[0];
    }

    if((flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
       && (flow->http_detected)
       && (packet->http_origin.len > 0)) {
      ndpi_protocol_match_result ret_match;

      ndpi_match_host_subprotocol(ndpi_struct, flow,
				  (char *)packet->http_origin.ptr,
				  packet->http_origin.len,
				  &ret_match,
				  NDPI_PROTOCOL_HTTP);
    }

    if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
      if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
	NDPI_LOG_INFO(ndpi_struct, "found HTTP/%s\n",
		      ndpi_get_proto_name(ndpi_struct, packet->detected_protocol_stack[0]));
	ndpi_int_http_add_connection(ndpi_struct, flow, packet->detected_protocol_stack[0], NDPI_PROTOCOL_CATEGORY_WEB);
	return; /* We have identified a sub-protocol so we're done */
      }
    }
  }

#if 0
  if(flow->http_detected)
    ndpi_http_parse_subprotocol(ndpi_struct, flow);
#endif

  if(flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN)
    flow->guessed_protocol_id = NDPI_PROTOCOL_HTTP;

  /* check for accept line */
  if(packet->accept_line.ptr != NULL) {
    NDPI_LOG_DBG2(ndpi_struct, "Accept line found %.*s\n",
		  packet->accept_line.len, packet->accept_line.ptr);
    if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask,
					NDPI_PROTOCOL_RTSP) != 0) {
      rtsp_parse_packet_acceptline(ndpi_struct, flow);
    }
  }

  if(packet->content_line.ptr != NULL && packet->content_line.len != 0) {
    NDPI_LOG_DBG2(ndpi_struct, "Content Type line found %.*s\n",
		  packet->content_line.len, packet->content_line.ptr);

    if((flow->http.content_type == NULL) && (packet->content_line.len > 0)) {
      int len = packet->content_line.len + 1;

      flow->http.content_type = ndpi_malloc(len);
      if(flow->http.content_type) {
	strncpy(flow->http.content_type, (char*)packet->content_line.ptr,
		packet->content_line.len);
	flow->http.content_type[packet->content_line.len] = '\0';
      }
    }

    if(flow->http_detected) {
      ndpi_protocol_match_result ret_match;

      ndpi_match_content_subprotocol(ndpi_struct, flow,
				     (char*)packet->content_line.ptr, packet->content_line.len,
				     &ret_match, NDPI_PROTOCOL_HTTP);
    }
  }

  ndpi_int_http_add_connection(ndpi_struct, flow, packet->detected_protocol_stack[0], NDPI_PROTOCOL_CATEGORY_WEB);
}

/* ************************************************************* */

static void check_http_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  /* Add here your paylod code check */
}

/* ************************************************************* */

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
		    STATIC_STRING_L("PATCH "),
		    STATIC_STRING_L("DELETE "),
		    STATIC_STRING_L("CONNECT "),
		    STATIC_STRING_L("PROPFIND "),
		    STATIC_STRING_L("REPORT ") };
static const char *http_fs = "CDGHOPR";

static u_int16_t http_request_url_offset(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  int i;

  NDPI_LOG_DBG2(ndpi_struct, "====>>>> HTTP: %c%c%c%c [len: %u]\n",
		non_ctrl(packet->payload[0]), non_ctrl(packet->payload[1]),
		non_ctrl(packet->payload[2]), non_ctrl(packet->payload[3]),
		packet->payload_packet_len);

  /* Check first char */
  if(!packet->payload_packet_len || !strchr(http_fs,packet->payload[0])) return 0;
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
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_XBOX);
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

	if(packet->payload_packet_len >= 12) {
	  char buf[4];

	  /* Set server HTTP response code */
	  strncpy(buf, (char*)&packet->payload[9], 3);
	  buf[3] = '\0';

	  flow->http.response_status_code = atoi(buf);
	  /* https://en.wikipedia.org/wiki/List_of_HTTP_status_codes */
	  if((flow->http.response_status_code < 100) || (flow->http.response_status_code > 509))
	    flow->http.response_status_code = 0; /* Out of range */
	}

	ndpi_parse_packet_line_info(ndpi_struct, flow);
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
      ookla_found:
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_CATEGORY_WEB);

	if(ndpi_struct->ookla_cache == NULL)
	  ndpi_struct->ookla_cache = ndpi_lru_cache_init(1024);

	if(packet->iph != NULL && ndpi_struct->ookla_cache != NULL) {
	  if(packet->tcp->source == htons(8080))
	    ndpi_lru_add_to_cache(ndpi_struct->ookla_cache, packet->iph->saddr, 1 /* dummy */);
	  else
	    ndpi_lru_add_to_cache(ndpi_struct->ookla_cache, packet->iph->daddr, 1 /* dummy */);
	}

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
	goto ookla_found;
      }

#if defined(NDPI_PROTOCOL_1KXUN) || defined(NDPI_PROTOCOL_IQIYI)
      /* check PPStream protocol or iQiyi service
	 (iqiyi is delivered by ppstream) */
      // substring in url
      if(ndpi_strnstr((const char*) &packet->payload[filename_start], "iqiyi.com",
		      (packet->payload_packet_len - filename_start)) != NULL) {
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
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP_PROXY, NDPI_PROTOCOL_CATEGORY_WEB);
        check_content_type_and_change_protocol(ndpi_struct, flow);
      }

      if(filename_start == 8 && (memcmp(packet->payload, "CONNECT ", 8) == 0)) {
	/* nathan@getoffmalawn.com */
        NDPI_LOG_INFO(ndpi_struct, "found HTTP_CONNECT\n");
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP_CONNECT, NDPI_PROTOCOL_CATEGORY_WEB);
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

	ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP, NDPI_PROTOCOL_CATEGORY_WEB);
	flow->http_detected = 1;
	NDPI_LOG_DBG2(ndpi_struct,
		      "HTTP START Found, we will look further for the response...\n");
	flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
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
	goto ookla_found;
      }
    }

    if((packet->payload_packet_len > 6) && memcmp(packet->payload, "HELLO ", 6) == 0) {
      /* This looks like Ookla */
      goto ookla_found;
    } else
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_OOKLA);

    /**
       At first check, if this is for sure a response packet
       (in another direction. If not, if HTTP is detected do nothing now and return,
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
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP, NDPI_PROTOCOL_CATEGORY_WEB);
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
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP, NDPI_PROTOCOL_CATEGORY_WEB);
      check_content_type_and_change_protocol(ndpi_struct, flow);
      return;
    }

    /* If we already detected the HTTP request, we can add the connection and then check for the sub-protocol */
    if(flow->http_detected) {
      NDPI_LOG_INFO(ndpi_struct, "found HTTP\n");
      ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP, NDPI_PROTOCOL_CATEGORY_WEB);
    }

    /* Parse packet line and we look for the subprotocols */
    ndpi_parse_packet_line_info(ndpi_struct, flow);
    check_content_type_and_change_protocol(ndpi_struct, flow);

    if(packet->packet_direction == 1 /* server -> client */)
      flow->http.num_response_headers += packet->http_num_headers; /* flow structs are initialized with zeros */

    if(packet->empty_line_position_set != 0 || flow->l4.tcp.http_empty_line_seen == 1) {
      NDPI_LOG_DBG2(ndpi_struct, "empty line. check_http_payload\n");
      check_http_payload(ndpi_struct, flow);
    }

    flow->l4.tcp.http_stage = 0;
    return;
  }
}

/* ********************************* */

static void ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  /* Break after 20 packets. */
  if(flow->packet_counter > 20) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    http_bitmask_exclude_other(flow);
    return;
  }

  NDPI_LOG_DBG(ndpi_struct, "search HTTP\n");
  ndpi_check_http_tcp(ndpi_struct, flow);
}

/* ********************************* */

ndpi_http_method ndpi_get_http_method(struct ndpi_detection_module_struct *ndpi_mod,
				      struct ndpi_flow_struct *flow) {
  if(!flow)
    return(NDPI_HTTP_METHOD_UNKNOWN);
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
			 NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("HTTP",ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_HTTP,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
