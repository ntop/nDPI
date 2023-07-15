/*
 * http.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

#include <assert.h>

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HTTP

#include "ndpi_api.h"

static const char* binary_file_mimes_e[] = { "exe", NULL };
static const char* binary_file_mimes_j[] = { "java-vm", NULL };
static const char* binary_file_mimes_v[] = { "vnd.ms-cab-compressed", "vnd.microsoft.portable-executable", NULL };
static const char* binary_file_mimes_x[] = { "x-msdownload", "x-dosexec", NULL };

static const char* download_file_mimes_b[] = { "bz", "bz2", NULL };
static const char* download_file_mimes_o[] = { "octet-stream", NULL };
static const char* download_file_mimes_x[] = { "x-tar", "x-zip", "x-bzip", NULL };

#define ATTACHMENT_LEN    3
static const char* binary_file_ext[] = {
					"exe",
					"msi",
					"cab",
					NULL
};

extern void ookla_add_to_cache(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow);

static void ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow);
static void ndpi_check_http_header(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow);

/* *********************************************** */

static void ndpi_set_binary_application_transfer(struct ndpi_detection_module_struct *ndpi_struct,
						 struct ndpi_flow_struct *flow,
						 char *msg) {
  /*
    Check known exceptions
  */
  if(ndpi_ends_with((char*)flow->host_server_name, ".windowsupdate.com"))
    ;
  else
    ndpi_set_risk(ndpi_struct, flow, NDPI_BINARY_APPLICATION_TRANSFER, msg);
 }

  /* *********************************************** */

static void ndpi_analyze_content_signature(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow) {
  u_int8_t set_risk = 0;
  const char *msg = NULL;

  if((flow->initial_binary_bytes_len >= 2) && (flow->initial_binary_bytes[0] == 0x4D) && (flow->initial_binary_bytes[1] == 0x5A))
    set_risk = 1, msg = "Found Windows Exe"; /* Win executable */
  else if((flow->initial_binary_bytes_len >= 4) && (flow->initial_binary_bytes[0] == 0x7F) && (flow->initial_binary_bytes[1] == 'E')
	  && (flow->initial_binary_bytes[2] == 'L') && (flow->initial_binary_bytes[3] == 'F'))
    set_risk = 1, msg = "Found Linux Exe"; /* Linux executable */
  else if((flow->initial_binary_bytes_len >= 4) && (flow->initial_binary_bytes[0] == 0xCF) && (flow->initial_binary_bytes[1] == 0xFA)
	  && (flow->initial_binary_bytes[2] == 0xED) && (flow->initial_binary_bytes[3] == 0xFE))
    set_risk = 1, msg = "Found Linux Exe"; /* Linux executable */
  else if((flow->initial_binary_bytes_len >= 3)
	  && (flow->initial_binary_bytes[0] == '#')
	  && (flow->initial_binary_bytes[1] == '!')
	  && (flow->initial_binary_bytes[2] == '/'))
    set_risk = 1, msg = "Found Unix Script"; /* Unix script (e.g. #!/bin/sh) */
  else if(flow->initial_binary_bytes_len >= 8) {
    u_int8_t exec_pattern[] = { 0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00 };

    if(memcmp(flow->initial_binary_bytes, exec_pattern, 8) == 0)
      set_risk = 1, msg = "Found Android Exe"; /* Dalvik Executable (Android) */
  }

  if(set_risk)
    ndpi_set_binary_application_transfer(ndpi_struct, flow, (char*)msg);
}

/* *********************************************** */

static int ndpi_search_http_tcp_again(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  if(packet->payload_packet_len == 0 || packet->tcp_retransmission)
    return 1;

  ndpi_search_http_tcp(ndpi_struct, flow);

#ifdef HTTP_DEBUG
  printf("=> %s()\n", __FUNCTION__);
#endif

  if(flow->extra_packets_func == NULL) {
    return(0); /* We're good now */
  }

  /* Possibly more processing */
  return(1);
}

/* *********************************************** */

static int ndpi_http_is_print(char c) {
  if(isprint(c) || (c == '\t') || (c == '\r') || (c == '\n'))
    return(1);
  else
    return(0);
}

/* *********************************************** */

static void ndpi_http_check_human_redeable_content(struct ndpi_detection_module_struct *ndpi_struct,
						   struct ndpi_flow_struct *flow,
						   const u_int8_t *content, u_int16_t content_len) {
  if(content_len >= 4) {
    NDPI_LOG_DBG(ndpi_struct, " [len: %u] [%02X %02X %02X %02X][%c%c%c%c]", content_len,
	   content[0], content[1], content[2], content[3],
	   content[0], content[1], content[2], content[3]
	   );

    if(ndpi_http_is_print(content[0]) && ndpi_http_is_print(content[1])
       && ndpi_http_is_print(content[2]) && ndpi_http_is_print(content[3])) {
      /* OK */
    } else {
      /* Looks bad: last resort check if it's gzipped [1F 8B 08 00] */

      if((content[0] == 0x1F)
	 && (content[1] == 0x8B)
	 && (content[2] == 0x08)
	 && (content[3] == 0x00)) {
	/* Looks like compressed data */
      } else {
	char str[32];

	snprintf(str, sizeof(str), "Susp content %02X%02X%02X%02X",
		 content[0], content[1], content[2], content[3]);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_CONTENT, str);
      }
    }
  }
}

/* *********************************************** */

static void ndpi_validate_http_content(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *double_ret = (const u_int8_t *)ndpi_strnstr((const char *)packet->payload, "\r\n\r\n", packet->payload_packet_len);

  NDPI_LOG_DBG(ndpi_struct, "==>>> [len: %u] ", packet->payload_packet_len);
  NDPI_LOG_DBG(ndpi_struct, "->> %.*s\n", packet->content_line.len, (const char *)packet->content_line.ptr);

  if(double_ret) {
    u_int len;

    len = packet->payload_packet_len - (double_ret - packet->payload);

    if(ndpi_strnstr((const char *)packet->content_line.ptr, "text/", packet->content_line.len)
       || ndpi_strnstr((const char *)packet->content_line.ptr, "/json", packet->content_line.len)
       || ndpi_strnstr((const char *)packet->content_line.ptr, "x-www-form-urlencoded", packet->content_line.len)
       ) {
      /* This is supposed to be a human-readeable text file */

      packet->http_check_content = 1;

      if(len >= 8 /* 4 chars for \r\n\r\n and at least 4 charts for content guess */) {
	double_ret += 4;

	ndpi_http_check_human_redeable_content(ndpi_struct, flow, double_ret, len);
      }
    }

    /* Final checks */

    if(ndpi_isset_risk(ndpi_struct, flow, NDPI_BINARY_APPLICATION_TRANSFER)
       && flow->http.user_agent && flow->http.content_type) {
      if(((strncmp((const char *)flow->http.user_agent, "Java/", 5) == 0))
	 &&
	 ((strcmp((const char *)flow->http.content_type, "application/java-vm") == 0))
	 ) {
	/*
	  Java downloads Java: Log4J:
	  https://corelight.com/blog/detecting-log4j-exploits-via-zeek-when-java-downloads-java
	*/

	ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, "Suspicious Log4J");
      }
    }

    NDPI_LOG_DBG(ndpi_struct, "\n");
  }

  if((flow->http.user_agent == NULL) || (flow->http.user_agent[0] == '\0'))
    ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_USER_AGENT, "Empty or missing User-Agent");
}

/* *********************************************** */

/* https://www.freeformatter.com/mime-types-list.html */
static ndpi_protocol_category_t ndpi_http_check_content(struct ndpi_detection_module_struct *ndpi_struct,
							struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(packet->content_line.len > 0) {
    u_int app_len = sizeof("application");

    if(packet->content_line.len > app_len) {
      const char *app     = (const char *)&packet->content_line.ptr[app_len];
      u_int app_len_avail = packet->content_line.len-app_len;

      if(strncasecmp(app, "mpeg", app_len_avail) == 0) {
	flow->guessed_category = flow->category = NDPI_PROTOCOL_CATEGORY_STREAMING;
	return(flow->category);
      } else {
	if(app_len_avail > 3) {
	  const char** cmp_mimes = NULL;

	  switch(app[0]) {
	  case 'b': cmp_mimes = download_file_mimes_b; break;
	  case 'o': cmp_mimes = download_file_mimes_o; break;
	  case 'x': cmp_mimes = download_file_mimes_x; break;
	  }

	  if(cmp_mimes != NULL) {
	    u_int8_t i;

	    for(i = 0; cmp_mimes[i] != NULL; i++) {
	      if(strncasecmp(app, cmp_mimes[i], app_len_avail) == 0) {
		flow->guessed_category = flow->category = NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT;
		NDPI_LOG_INFO(ndpi_struct, "found executable HTTP transfer");
		break;
	      }
	    }
	  }

	  /* ***************************************** */

	  switch(app[0]) {
	  case 'e': cmp_mimes = binary_file_mimes_e; break;
	  case 'j': cmp_mimes = binary_file_mimes_j; break;
	  case 'v': cmp_mimes = binary_file_mimes_v; break;
	  case 'x': cmp_mimes = binary_file_mimes_x; break;
	  }

	  if(cmp_mimes != NULL) {
	    u_int8_t i;

	    for(i = 0; cmp_mimes[i] != NULL; i++) {
	      if(strncasecmp(app, cmp_mimes[i], app_len_avail) == 0) {
		char str[64];

		snprintf(str, sizeof(str), "Found mime exe %s", cmp_mimes[i]);
		flow->guessed_category = flow->category = NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT;
		ndpi_set_binary_application_transfer(ndpi_struct, flow, str);
		NDPI_LOG_INFO(ndpi_struct, "Found executable HTTP transfer");
	      }
	    }
	  }
	}
      }
    }

    /* check for attachment */
    if(packet->content_disposition_line.len > 0) {
      u_int8_t attachment_len = sizeof("attachment; filename");

      if(packet->content_disposition_line.len > attachment_len &&
         strncmp((char *)packet->content_disposition_line.ptr, "attachment; filename", 20) == 0) {
	u_int8_t filename_len = packet->content_disposition_line.len - attachment_len;
	int i;

	if(packet->content_disposition_line.ptr[attachment_len] == '\"') {
	  if(packet->content_disposition_line.ptr[packet->content_disposition_line.len-1] != '\"') {
	    //case: filename="file_name
	    if(filename_len >= 2) {
	      flow->http.filename = ndpi_malloc(filename_len);
	      if(flow->http.filename != NULL) {
	        strncpy(flow->http.filename, (char*)packet->content_disposition_line.ptr+attachment_len+1, filename_len-1);
	        flow->http.filename[filename_len-1] = '\0';
	      }
	    }
	  }
	  else if(filename_len >= 2) {
	    //case: filename="file_name"
	    flow->http.filename = ndpi_malloc(filename_len-1);

	    if(flow->http.filename != NULL) {
	      strncpy(flow->http.filename, (char*)packet->content_disposition_line.ptr+attachment_len+1,
		      filename_len-2);
	      flow->http.filename[filename_len-2] = '\0';
	    }
	  }
	} else {
	  //case: filename=file_name
	  flow->http.filename = ndpi_malloc(filename_len+1);

	  if(flow->http.filename != NULL) {
	    strncpy(flow->http.filename, (char*)packet->content_disposition_line.ptr+attachment_len, filename_len);
	    flow->http.filename[filename_len] = '\0';
	  }
	}

	if(filename_len > ATTACHMENT_LEN) {
	  attachment_len += filename_len-ATTACHMENT_LEN-1;

	  if((attachment_len+ATTACHMENT_LEN) <= packet->content_disposition_line.len) {
	    for(i = 0; binary_file_ext[i] != NULL; i++) {
	      /* Use memcmp in case content-disposition contains binary data */
	      if(memcmp(&packet->content_disposition_line.ptr[attachment_len],
			binary_file_ext[i], ATTACHMENT_LEN) == 0) {
		char str[64];

		snprintf(str, sizeof(str), "Found file extn %s", binary_file_ext[i]);
		flow->guessed_category = flow->category = NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT;
		ndpi_set_binary_application_transfer(ndpi_struct, flow, str);
		NDPI_LOG_INFO(ndpi_struct, "found executable HTTP transfer");
		return(flow->category);
	      }
	    }
	  }
	}
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
					 u_int16_t master_protocol) {
#ifdef HTTP_DEBUG
  printf("=> %s()\n", __FUNCTION__);
#endif

  /* Update the classification only if we don't already have master + app;
     for example don't change the protocols if we have already detected a
     sub-protocol via the (content-matched) subprotocols logic (i.e.
     MPEGDASH, SOAP, ....) */
  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
    NDPI_LOG_DBG2(ndpi_struct, "Master: %d\n", master_protocol);
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN,
			       master_protocol, NDPI_CONFIDENCE_DPI);
  }

  flow->max_extra_packets_to_check = 8;
  flow->extra_packets_func = ndpi_search_http_tcp_again;
}

/* ************************************************************* */

static void setHttpUserAgent(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow, char *ua) {
  if(    !strcmp(ua, "Windows NT 5.0"))  ua = "Windows 2000";
  else if(!strcmp(ua, "Windows NT 5.1"))  ua = "Windows XP";
  else if(!strcmp(ua, "Windows NT 5.2"))  ua = "Windows Server 2003";
  else if(!strcmp(ua, "Windows NT 6.0"))  ua = "Windows Vista";
  else if(!strcmp(ua, "Windows NT 6.1"))  ua = "Windows 7";
  else if(!strcmp(ua, "Windows NT 6.2"))  ua = "Windows 8";
  else if(!strcmp(ua, "Windows NT 6.3"))  ua = "Windows 8.1";
  else if(!strcmp(ua, "Windows NT 10.0")) ua = "Windows 10";

  /* Good reference for future implementations:
   * https://github.com/ua-parser/uap-core/blob/master/regexes.yaml */

  if(flow->http.detected_os == NULL)
    flow->http.detected_os = ndpi_strdup(ua);
}

/* ************************************************************* */

static void ndpi_http_parse_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow,
					int hostname_just_set) {
  u_int16_t master_protocol;
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  master_protocol = NDPI_PROTOCOL_HTTP;
  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN)
    master_protocol = flow->detected_protocol_stack[1];
  else if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP_CONNECT ||
          flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP_PROXY)
    master_protocol = flow->detected_protocol_stack[0];

  if(packet->server_line.len > 7 &&
     strncmp((const char *)packet->server_line.ptr, "ntopng ", 7) == 0) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NTOP, NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
    ndpi_unset_risk(ndpi_struct, flow, NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT);
  }

  /* Matching on Content-Type.
      OCSP:  application/ocsp-request, application/ocsp-response
  */
  /* We overwrite any previous sub-classification (example: via hostname) */
  if(packet->content_line.len > 17 &&
     strncmp((const char *)packet->content_line.ptr, "application/ocsp-", 17) == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "Found OCSP\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OCSP, master_protocol, NDPI_CONFIDENCE_DPI);
  }

  if(flow->http.method == NDPI_HTTP_METHOD_RPC_IN_DATA ||
     flow->http.method == NDPI_HTTP_METHOD_RPC_OUT_DATA) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RPC, master_protocol, NDPI_CONFIDENCE_DPI);
  }

  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN &&
     hostname_just_set && flow->host_server_name[0] != '\0') {
    ndpi_match_hostname_protocol(ndpi_struct, flow,
				 master_protocol,
				 flow->host_server_name,
				 strlen(flow->host_server_name));
  }

  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN &&
     packet->http_origin.len > 0) {
    ndpi_protocol_match_result ret_match;
    char *ptr, *origin_hostname;
    size_t origin_hostname_len;

    /* Origin syntax:
        Origin: null
        Origin: <scheme>://<hostname>
        Origin: <scheme>://<hostname>:<port>
    Try extracting hostname */

    ptr = ndpi_strnstr((const char *)packet->http_origin.ptr, "://", packet->http_origin.len);
    if(ptr) {
      origin_hostname = ptr + 3;
      origin_hostname_len = packet->http_origin.len - (ptr - (char *)packet->http_origin.ptr) - 3;
      ptr = ndpi_strnstr(origin_hostname, ":", origin_hostname_len);
      if(ptr) {
        origin_hostname_len = ptr - origin_hostname;
      }
      NDPI_LOG_DBG2(ndpi_struct, "Origin: [%.*s] -> [%.*s]\n", packet->http_origin.len, packet->http_origin.ptr,
		    (int)origin_hostname_len, origin_hostname);
      /* We already checked hostname...*/
      if(strncmp(origin_hostname, flow->host_server_name, origin_hostname_len) != 0) {
        ndpi_match_host_subprotocol(ndpi_struct, flow,
				    origin_hostname,
				    origin_hostname_len,
				    &ret_match,
				    master_protocol);
      }
    }
  }

  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN &&
     flow->http.url &&
     ((strstr(flow->http.url, ":8080/downloading?n=0.") != NULL) ||
      (strstr(flow->http.url, ":8080/upload?n=0.") != NULL))) {
    /* This looks like Ookla speedtest */
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, master_protocol, NDPI_CONFIDENCE_DPI);
    ookla_add_to_cache(ndpi_struct, flow);
  }

  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN &&
     flow->http.url != NULL &&
     strstr(flow->http.url, "micloud.xiaomi.net") != NULL) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_XIAOMI, master_protocol, NDPI_CONFIDENCE_DPI);
  }

  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN &&
     packet->referer_line.len > 0 &&
     ndpi_strnstr((const char *)packet->referer_line.ptr, "www.speedtest.net", packet->referer_line.len)) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, master_protocol, NDPI_CONFIDENCE_DPI);
    ookla_add_to_cache(ndpi_struct, flow);
  }

  /* WindowsUpdate over some kind of CDN */
  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN &&
     flow->http.user_agent && flow->http.url &&
     (strstr(flow->http.url, "delivery.mp.microsoft.com/") ||
      strstr(flow->http.url, "download.windowsupdate.com/")) &&
     strstr(flow->http.user_agent, "Microsoft-Delivery-Optimization/") &&
     ndpi_isset_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST)) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WINDOWS_UPDATE, master_protocol, NDPI_CONFIDENCE_DPI);
  }

  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN &&
     packet->payload_packet_len >= 23 &&
     memcmp(packet->payload, "<policy-file-request/>", 23) == 0) {
    /*
      <policy-file-request/>
      <cross-domain-policy>
      <allow-access-from domain="*.ookla.com" to-ports="8080"/>
      <allow-access-from domain="*.speedtest.net" to-ports="8080"/>
      </cross-domain-policy>
     */
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, master_protocol, NDPI_CONFIDENCE_DPI);
    ookla_add_to_cache(ndpi_struct, flow);
  }
}

/* ************************************************************* */

static void ndpi_check_user_agent(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  char const *ua, size_t ua_len) {
  char *double_slash;

  if((!ua) || (ua[0] == '\0'))
    return;

  if (ua_len > 12)
  {
    size_t i, upper_case_count = 0;

    for (i = 0; i < ua_len; ++i)
    {
      /*
       * We assume at least one non alpha char.
       * e.g. ' ', '-' or ';' ...
       */
      if (isalpha(ua[i]) == 0)
      {
        break;
      }
      if (isupper(ua[i]) != 0)
      {
        upper_case_count++;
      }
    }

    if (i == ua_len) {
      float upper_case_ratio = (float)upper_case_count / (float)ua_len;

      if (upper_case_ratio >= 0.2f) {
	char str[64];

	snprintf(str, sizeof(str), "UA %s", ua);
        ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_USER_AGENT, str);
      }
    }
  }

  if((!strncmp(ua, "<?", 2))
     || strchr(ua, '$')
     ) {
    char str[64];

    snprintf(str, sizeof(str), "UA %s", ua);
    ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_USER_AGENT, str);
  }

  if((double_slash = strstr(ua, "://")) != NULL) {
    if(double_slash != ua) /* We're not at the beginning of the user agent */{
      if((double_slash[-1] != 'p') /* http:// */
	 && (double_slash[-1] != 's') /* https:// */) {
	char str[64];

	snprintf(str, sizeof(str), "UA %s", ua);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_USER_AGENT, str);
      }
    }
  }

  /* no else */
  if(!strncmp(ua, "jndi:ldap://", 12)) /* Log4J */ {
    ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, "Suspicious Log4J");
  } else if(
	  (ua_len < 4)      /* Too short */
	  || (ua_len > 256) /* Too long  */
	  || (!strncmp(ua, "test", 4))
	  || strchr(ua, '{')
	  || strchr(ua, '}')
	  ) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_USER_AGENT, "Suspicious Log4J");
  }

  /*
    Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)
    Amazon-Route53-Health-Check-Service (ref 68784dad-be98-49e4-a63c-9fbbe2816d7c; report http://amzn.to/1vsZADi)
    Anonymous Crawler/1.0 (Webcrawler developed with StormCrawler; http://example.com/; webcrawler@example.com)
   */
  if((strstr(ua, "+http:") != NULL)
     || (strstr(ua, " http:") != NULL)
     || ndpi_strncasestr(ua, "Crawler", ua_len)
     || ndpi_strncasestr(ua, "Bot", ua_len) /* bot/robot */
     ) {
    char str[64];

    snprintf(str, sizeof(str), "UA %s", ua);

    ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_CRAWLER_BOT, str);
  }
}

/* ************************************************************* */

void http_process_user_agent(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow,
			     const u_int8_t *ua_ptr, u_int16_t ua_ptr_len) {
  /**
      Format examples:
      Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) ....
      Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0
   */
  if(ua_ptr_len > 7) {
    char ua[256];
    u_int mlen = ndpi_min(ua_ptr_len, sizeof(ua)-1);

    strncpy(ua, (const char *)ua_ptr, mlen);
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
    }
  }

  if(ndpi_user_agent_set(flow, ua_ptr, ua_ptr_len) != NULL) {
    ndpi_unset_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_USER_AGENT);
    ndpi_check_user_agent(ndpi_struct, flow, flow->http.user_agent, ua_ptr_len);
  } else {
    NDPI_LOG_DBG2(ndpi_struct, "Could not set HTTP user agent (already set?)\n");
  }

  NDPI_LOG_DBG2(ndpi_struct, "User Agent Type line found %.*s\n",
		ua_ptr_len, ua_ptr);
}

/* ************************************************************* */

static void ndpi_check_numeric_ip(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  char *ip, u_int ip_len) {
  char buf[22], *double_dot;
  struct in_addr ip_addr;

  strncpy(buf, ip, ip_len);
  buf[ip_len] = '\0';

  if((double_dot = strchr(buf, ':')) != NULL)
    double_dot[0] = '\0';

  ip_addr.s_addr = inet_addr(buf);
  if(strcmp(inet_ntoa(ip_addr), buf) == 0) {
    char str[64];

    snprintf(str, sizeof(str), "Found host %s", buf);
    ndpi_set_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST, str);
  }
}

/* ************************************************************* */

static void ndpi_check_http_url(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				char *url) {
  if(strstr(url, "<php>") != NULL /* PHP code in the URL */)
    ndpi_set_risk(ndpi_struct, flow, NDPI_URL_POSSIBLE_RCE_INJECTION, "PHP code in URL");
  else if(strncmp(url, "/shell?", 7) == 0)
    ndpi_set_risk(ndpi_struct, flow, NDPI_URL_POSSIBLE_RCE_INJECTION, "Possible WebShell detected");
  else if(strncmp(url, "/.", 2) == 0)
    ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, "URL starting with dot");
}

/* ************************************************************* */

#define MIN_APACHE_VERSION 2004000 /* 2.4.X  [https://endoflife.date/apache] */
#define MIN_NGINX_VERSION  1022000 /* 1.22.0 [https://endoflife.date/nginx]  */

static void ndpi_check_http_server(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow,
				   const char *server, u_int server_len) {
  if(server[0] != '\0') {
    if(server_len > 7) {
      u_int off, i;

      if((strncasecmp(server, "Apache/", off = 7) == 0) /* X.X.X */
	 || (strncasecmp(server, "nginx/", off = 6) == 0) /* X.X.X */) {
	u_int j, a, b, c;
	char buf[16] = { '\0' };

	for(i=off, j=0; (i<server_len) && (j<sizeof(buf)-1)
	      && (isdigit(server[i]) || (server[i] == '.')); i++)
	  buf[j++] = server[i];

	if(sscanf(buf, "%d.%d.%d", &a, &b, &c) == 3) {
	  u_int32_t version = (a * 1000000) + (b * 1000) + c;
	  char msg[64];

	  if((off == 7) && (version < MIN_APACHE_VERSION)) {
	    snprintf(msg, sizeof(msg), "Obsolete Apache server %s", buf);
	    ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_OBSOLETE_SERVER, msg);
	  } else if((off == 6) && (version < MIN_NGINX_VERSION)) {
	    snprintf(msg, sizeof(msg), "Obsolete nginx server %s", buf);
	    ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_OBSOLETE_SERVER, msg);
	  }
	}
      }

      /* Check server content */
      for(i=0; i<server_len; i++) {
	if(!isprint(server[i])) {
	  ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, "Suspicious Agent");
	  break;
	}
      }
    }
  }
}

/* ************************************************************* */

/**
   NOTE
   ndpi_parse_packet_line_info is in ndpi_main.c
*/
static void check_content_type_and_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int len;
  int hostname_just_set = 0;

  if((flow->http.url == NULL)
     && (packet->http_url_name.len > 0)
     && (packet->host_line.len > 0)) {
    int len = packet->http_url_name.len + packet->host_line.len + 1;

    if(isdigit(packet->host_line.ptr[0])
       && (packet->host_line.len < 21))
      ndpi_check_numeric_ip(ndpi_struct, flow, (char*)packet->host_line.ptr, packet->host_line.len);

    flow->http.url = ndpi_malloc(len);
    if(flow->http.url) {
      u_int offset = 0, host_end = 0;

      if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP_CONNECT) {
	strncpy(flow->http.url, (char*)packet->http_url_name.ptr,
		packet->http_url_name.len);

	flow->http.url[packet->http_url_name.len] = '\0';
      } else {
	/* Check if we pass through a proxy (usually there is also the Via: ... header) */
	if(strncmp((char*)packet->http_url_name.ptr, "http://", 7) != 0) {
	  strncpy(flow->http.url, (char*)packet->host_line.ptr, offset = packet->host_line.len);
	  host_end = packet->host_line.len;
	}

	if((packet->host_line.len == packet->http_url_name.len)
	   && (strncmp((char*)packet->host_line.ptr,
		       (char*)packet->http_url_name.ptr, packet->http_url_name.len) == 0))
	  ;
	else {
	  strncpy(&flow->http.url[offset], (char*)packet->http_url_name.ptr,
		  packet->http_url_name.len);
	  offset += packet->http_url_name.len;
	}

	flow->http.url[offset] = '\0';
      }

      ndpi_check_http_url(ndpi_struct, flow, &flow->http.url[host_end]);
    }
  }

  if(packet->http_method.ptr != NULL)
    flow->http.method = ndpi_http_str2method((const char*)packet->http_method.ptr,
					     (u_int16_t)packet->http_method.len);

  if(packet->server_line.ptr != NULL)
    ndpi_check_http_server(ndpi_struct, flow, (const char *)packet->server_line.ptr, packet->server_line.len);

  if(packet->user_agent_line.ptr != NULL) {
    http_process_user_agent(ndpi_struct, flow, packet->user_agent_line.ptr, packet->user_agent_line.len);
  }

  if(packet->forwarded_line.ptr != NULL) {
    if(flow->http.nat_ip == NULL) {
      len = packet->forwarded_line.len;
      flow->http.nat_ip = ndpi_malloc(len + 1);
      if(flow->http.nat_ip != NULL) {
        strncpy(flow->http.nat_ip, (char*)packet->forwarded_line.ptr, len);
        flow->http.nat_ip[len] = '\0';
      }
    }
  }

  if(packet->server_line.ptr != NULL) {
    if(flow->http.server == NULL) {
      len = packet->server_line.len + 1;
      flow->http.server = ndpi_malloc(len);
      if(flow->http.server) {
        strncpy(flow->http.server, (char*)packet->server_line.ptr,
                packet->server_line.len);
	flow->http.server[packet->server_line.len] = '\0';
      }
    }
  }

  if(packet->authorization_line.ptr != NULL) {
    NDPI_LOG_DBG2(ndpi_struct, "Authorization line found %.*s\n",
		  packet->authorization_line.len, packet->authorization_line.ptr);

    if(ndpi_strncasestr((const char*)packet->authorization_line.ptr,
			"Basic", packet->authorization_line.len)
       || ndpi_strncasestr((const char*)packet->authorization_line.ptr,
			   "Digest", packet->authorization_line.len)) {
      ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS,
		    "Found credentials in HTTP Auth Line");
    }
  }

  if(packet->content_line.ptr != NULL) {
    NDPI_LOG_DBG2(ndpi_struct, "Content Type line found %.*s\n",
		  packet->content_line.len, packet->content_line.ptr);

    if(flow->http.response_status_code == 0) {
      /* Request */
      if((flow->http.request_content_type == NULL) && (packet->content_line.len > 0)) {
	int len = packet->content_line.len + 1;

	flow->http.request_content_type = ndpi_malloc(len);
	if(flow->http.request_content_type) {
	  strncpy(flow->http.request_content_type, (char*)packet->content_line.ptr,
		  packet->content_line.len);
	  flow->http.request_content_type[packet->content_line.len] = '\0';
	}
      }
    } else {
      /* Response */
      if((flow->http.content_type == NULL) && (packet->content_line.len > 0)) {
	int len = packet->content_line.len + 1;

	flow->http.content_type = ndpi_malloc(len);
	if(flow->http.content_type) {
	  strncpy(flow->http.content_type, (char*)packet->content_line.ptr,
		  packet->content_line.len);
	  flow->http.content_type[packet->content_line.len] = '\0';

	  flow->guessed_category = flow->category = ndpi_http_check_content(ndpi_struct, flow);
	}
      }
    }
  }

  /* check for host line (only if we don't already have an hostname) */
  if(packet->host_line.ptr != NULL && flow->host_server_name[0] == '\0') {

    NDPI_LOG_DBG2(ndpi_struct, "HOST line found %.*s\n",
		  packet->host_line.len, packet->host_line.ptr);

    /* Copy result for nDPI apps */
    ndpi_hostname_sni_set(flow, packet->host_line.ptr, packet->host_line.len);

    if(strlen(flow->host_server_name) > 0) {
      char *double_col;
      int a, b, c, d;

      hostname_just_set = 1;

      if(ndpi_is_valid_hostname(flow->host_server_name,
				strlen(flow->host_server_name)) == 0) {
	char str[128];

	snprintf(str, sizeof(str), "Invalid host %s", flow->host_server_name);
	ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, str);

	/* This looks like an attack */
	ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, NULL);
      }

      double_col = strchr((char*)flow->host_server_name, ':');
      if(double_col) double_col[0] = '\0';
      if(ndpi_struct->packet.iph
         && (sscanf(flow->host_server_name, "%d.%d.%d.%d", &a, &b, &c, &d) == 4)) {
        /* IPv4 */

        if(ndpi_struct->packet.iph->daddr != inet_addr(flow->host_server_name)) {
	  char buf[64], msg[128];

	  snprintf(msg, sizeof(msg), "Expected %s, found %s",
		   ndpi_intoav4(ntohl(ndpi_struct->packet.iph->daddr), buf, sizeof(buf)), flow->host_server_name);
	  ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, msg);
        }
      }
    }

  }

  ndpi_http_parse_subprotocol(ndpi_struct, flow, hostname_just_set);

  if(hostname_just_set && strlen(flow->host_server_name) > 0) {
    ndpi_check_dga_name(ndpi_struct, flow, flow->host_server_name, 1, 0);
  }

  if(flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN)
    flow->guessed_protocol_id = NDPI_PROTOCOL_HTTP;

  ndpi_check_http_header(ndpi_struct, flow);
}

/* ************************************************************* */

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
static uint8_t non_ctrl(uint8_t c) {
  return c < 32 ? '.':c;
}
#endif

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
		    STATIC_STRING_L("REPORT "),
		    STATIC_STRING_L("RPC_IN_DATA "), STATIC_STRING_L("RPC_OUT_DATA ")
};
static const char *http_fs = "CDGHOPR";

static u_int16_t http_request_url_offset(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  unsigned int i;

  NDPI_LOG_DBG2(ndpi_struct, "====>>>> HTTP: %c%c%c%c [len: %u]\n",
		packet->payload_packet_len > 0 ? non_ctrl(packet->payload[0]) : '.',
		packet->payload_packet_len > 1 ? non_ctrl(packet->payload[1]) : '.',
		packet->payload_packet_len > 2 ? non_ctrl(packet->payload[2]) : '.',
		packet->payload_packet_len > 3 ? non_ctrl(packet->payload[3]) : '.',
		packet->payload_packet_len);

  /* Check first char */
  if(!packet->payload_packet_len || !strchr(http_fs,packet->payload[0]))
    return 0;

  /**
     FIRST PAYLOAD PACKET FROM CLIENT
  **/
  for(i=0; i < sizeof(http_methods)/sizeof(http_methods[0]); i++) {
    if(packet->payload_packet_len >= http_methods[i].len &&
       strncasecmp((const char*)packet->payload,http_methods[i].str,http_methods[i].len) == 0) {
      size_t url_start = http_methods[i].len;
      while (url_start < packet->payload_packet_len &&
             url_start < http_methods[i].len + 2048 && /* We assume 2048 chars as maximum for URLs. */
             packet->payload[url_start] == ' ') { url_start++; }
      NDPI_LOG_DBG2(ndpi_struct, "HTTP: %sFOUND\n",http_methods[i].str);
      return url_start;
    }
  }
  return 0;
}

/* *********************************************************************************************** */

/* Trick to speed-up detection */
static const char* suspicious_http_header_keys_A[] = { "Arch", NULL};
static const char* suspicious_http_header_keys_C[] = { "Cores", NULL};
static const char* suspicious_http_header_keys_M[] = { "Mem", NULL};
static const char* suspicious_http_header_keys_O[] = { "Os", "Osname", "Osversion", NULL};
static const char* suspicious_http_header_keys_R[] = { "Root", NULL};
static const char* suspicious_http_header_keys_S[] = { "S", NULL};
static const char* suspicious_http_header_keys_T[] = { "TLS_version", NULL};
static const char* suspicious_http_header_keys_U[] = { "Uuid", NULL};
static const char* suspicious_http_header_keys_X[] = { "X-Hire-Me", NULL};

static int is_a_suspicious_header(const char* suspicious_headers[], struct ndpi_int_one_line_struct packet_line) {
  int i;
  unsigned int header_len;
  const u_int8_t* header_limit;

  if((header_limit = memchr(packet_line.ptr, ':', packet_line.len))) {
    header_len = header_limit - packet_line.ptr;
    for(i=0; suspicious_headers[i] != NULL; i++) {
      if(!strncasecmp((const char*) packet_line.ptr,
		      suspicious_headers[i], header_len))
	return 1;
    }
  }

  return 0;
}

/* *********************************************************************************************** */

static void ndpi_check_http_header(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow) {
  u_int32_t i;
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  for(i=0; (i < packet->parsed_lines)
	&& (packet->line[i].ptr != NULL)
	&& (packet->line[i].len > 0); i++) {
    switch(packet->line[i].ptr[0]) {
    case 'A':
      if(is_a_suspicious_header(suspicious_http_header_keys_A, packet->line[i])) {
	char str[64];

	snprintf(str, sizeof(str), "Found %.*s", packet->line[i].len, packet->line[i].ptr);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, str);
	return;
      }
      break;
    case 'C':
      if(is_a_suspicious_header(suspicious_http_header_keys_C, packet->line[i])) {
	char str[64];

	snprintf(str, sizeof(str), "Found %.*s", packet->line[i].len, packet->line[i].ptr);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, str);
	return;
      }
      break;
    case 'M':
      if(is_a_suspicious_header(suspicious_http_header_keys_M, packet->line[i])) {
	char str[64];

	snprintf(str, sizeof(str), "Found %.*s", packet->line[i].len, packet->line[i].ptr);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, str);
	return;
      }
      break;
    case 'O':
      if(is_a_suspicious_header(suspicious_http_header_keys_O, packet->line[i])) {
	char str[64];

	snprintf(str, sizeof(str), "Found %.*s", packet->line[i].len, packet->line[i].ptr);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, str);
	return;
      }
      break;
    case 'R':
      if(is_a_suspicious_header(suspicious_http_header_keys_R, packet->line[i])) {
	char str[64];

	snprintf(str, sizeof(str), "Found %.*s", packet->line[i].len, packet->line[i].ptr);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, str);
	return;
      }
      break;
    case 'S':
      if(is_a_suspicious_header(suspicious_http_header_keys_S, packet->line[i])) {
	char str[64];

	snprintf(str, sizeof(str), "Found %.*s", packet->line[i].len, packet->line[i].ptr);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, str);
	return;
      }
      break;
    case 'T':
      if(is_a_suspicious_header(suspicious_http_header_keys_T, packet->line[i])) {
	char str[64];

	snprintf(str, sizeof(str), "Found %.*s", packet->line[i].len, packet->line[i].ptr);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, str);
	return;
      }
      break;
    case 'U':
      if(is_a_suspicious_header(suspicious_http_header_keys_U, packet->line[i])) {
	char str[64];

	snprintf(str, sizeof(str), "Found %.*s", packet->line[i].len, packet->line[i].ptr);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, str);
	return;
      }
      break;
    case 'X':
      if(is_a_suspicious_header(suspicious_http_header_keys_X, packet->line[i])) {
	char str[64];

	snprintf(str, sizeof(str), "Found %.*s", packet->line[i].len, packet->line[i].ptr);
	ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER, str);
	return;
      }

      break;
    }
  }
}

static void parse_response_code(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  char buf[4];
  char ec[48];

  if(packet->payload_packet_len >= 12) {
    /* Set server HTTP response code */
    strncpy(buf, (char*)&packet->payload[9], 3);
    buf[3] = '\0';

    flow->http.response_status_code = atoi(buf);
    NDPI_LOG_DBG2(ndpi_struct, "Response code %d\n", flow->http.response_status_code);

    /* https://en.wikipedia.org/wiki/List_of_HTTP_status_codes */
    if((flow->http.response_status_code < 100) || (flow->http.response_status_code > 509))
      flow->http.response_status_code = 0; /* Out of range */

    if(flow->http.response_status_code >= 400) {
      snprintf(ec, sizeof(ec), "HTTP Error Code %u", flow->http.response_status_code);
      ndpi_set_risk(ndpi_struct, flow, NDPI_ERROR_CODE_DETECTED, ec);

      if(flow->http.url != NULL) {
        /* Let's check for Wordpress */
        char *slash = strchr(flow->http.url, '/');

	if(slash != NULL &&
           (((flow->http.method == NDPI_HTTP_METHOD_POST) && (strncmp(slash, "/wp-admin/", 10) == 0))
	    || ((flow->http.method == NDPI_HTTP_METHOD_GET) && (strncmp(slash, "/wp-content/uploads/", 20) == 0))
	   )) {
          /* Example of popular exploits https://www.wordfence.com/blog/2022/05/millions-of-attacks-target-tatsu-builder-plugin/ */
          ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, "Possible Wordpress Exploit");
	}
      }
    }
  }
}

static int is_request(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t filename_start;

  filename_start = http_request_url_offset(ndpi_struct, flow);
  /* This check is required as RTSP is pretty similiar to HTTP */
  if(filename_start > 0 &&
     strncasecmp((const char *)packet->payload + filename_start,
                 "rtsp://", ndpi_min(7, packet->payload_packet_len - filename_start)) == 0)
    return 0;
  return filename_start;
}

static int is_response(struct ndpi_detection_module_struct *ndpi_struct,
		       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  if(packet->payload_packet_len >= 7 &&
     strncasecmp((const char *)packet->payload, "HTTP/1.", 7) == 0)
    return 1;
  return 0;
}

static void process_request(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow,
			    u_int16_t filename_start) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t master_protocol;

  ndpi_parse_packet_line_info(ndpi_struct, flow);

  master_protocol = NDPI_PROTOCOL_HTTP;

  if(packet->parsed_lines == 0 ||
     !(packet->line[0].len >= (9 + filename_start) &&
       strncasecmp((const char *)&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0)) {
    NDPI_LOG_DBG2(ndpi_struct, "Request with an incomplete or invalid first line\n");
    /* Since we don't save data across different packets, we will never have
       the complete url: we can't check for HTTP_PROXY */
    if(filename_start == 8 &&
       strncasecmp((const char *)packet->payload, "CONNECT ", 8) == 0) {
      master_protocol = NDPI_PROTOCOL_HTTP_CONNECT;
    }
  } else {
    /* First line is complete (example: "GET / HTTP/1.1"): extract url */

    packet->http_url_name.ptr = &packet->payload[filename_start];
    packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

    packet->http_method.ptr = packet->line[0].ptr;
    packet->http_method.len = filename_start - 1;

    /* Set the HTTP requested version: 0=HTTP/1.0 and 1=HTTP/1.1 */
    if(memcmp(&packet->line[0].ptr[packet->line[0].len - 1], "1", 1) == 0)
      flow->http.request_version = 1;
    else
      flow->http.request_version = 0;

    if(packet->http_url_name.len > 7 &&
       !strncasecmp((const char*) packet->http_url_name.ptr, "http://", 7)) {
      master_protocol = NDPI_PROTOCOL_HTTP_PROXY;
    }
    if(filename_start == 8 &&
       strncasecmp((const char *)packet->payload, "CONNECT ", 8) == 0) {
      master_protocol = NDPI_PROTOCOL_HTTP_CONNECT;
    }
  }
  ndpi_int_http_add_connection(ndpi_struct, flow, master_protocol);
  check_content_type_and_change_protocol(ndpi_struct, flow);

  if(flow->http.user_agent == NULL ||
     flow->http.user_agent[0] == '\0') {
    ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_USER_AGENT, "Empty or missing User-Agent");
  }
}

static void process_response(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow) {

  ndpi_parse_packet_line_info(ndpi_struct, flow);
  parse_response_code(ndpi_struct, flow);
  check_content_type_and_change_protocol(ndpi_struct, flow);

  ndpi_validate_http_content(ndpi_struct, flow);
}

static void reset(struct ndpi_detection_module_struct *ndpi_struct,
		  struct ndpi_flow_struct *flow) {

  NDPI_LOG_DBG2(ndpi_struct, "Reset status and risks\n");

  /* Reset everthing in flow->http.
     TODO: Could we be smarter? Probably some info don't change across
     different req-res transactions... */

  flow->http.method = 0;
  flow->http.request_version = 0;
  flow->http.response_status_code = 0;
  if(flow->http.url) {
    ndpi_free(flow->http.url);
    flow->http.url = NULL;
  }
  if(flow->http.content_type) {
    ndpi_free(flow->http.content_type);
    flow->http.content_type = NULL;
  }
  if(flow->http.request_content_type) {
    ndpi_free(flow->http.request_content_type);
    flow->http.request_content_type = NULL;
  }
  if(flow->http.user_agent) {
    ndpi_free(flow->http.user_agent);
    flow->http.user_agent = NULL;
  }
  if(flow->http.server) {
    ndpi_free(flow->http.server);
    flow->http.server = NULL;
  }
  if(flow->http.detected_os) {
    ndpi_free(flow->http.detected_os);
    flow->http.detected_os = NULL;
  }
  if(flow->http.nat_ip) {
    ndpi_free(flow->http.nat_ip);
    flow->http.nat_ip = NULL;
  }
  if(flow->http.filename) {
    ndpi_free(flow->http.filename);
    flow->http.filename = NULL;
  }

  /* Reset flow risks. We should reset only those risks triggered by
     the previous HTTP response... */
  /* TODO */
  ndpi_unset_risk(ndpi_struct, flow, NDPI_BINARY_APPLICATION_TRANSFER);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_CONTENT);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_USER_AGENT);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_HTTP_CRAWLER_BOT);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_URL_POSSIBLE_RCE_INJECTION);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_HTTP_OBSOLETE_SERVER);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_HTTP_SUSPICIOUS_HEADER);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_ERROR_CODE_DETECTED);
  ndpi_unset_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET);
}

static void ndpi_check_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t filename_start;

  NDPI_LOG_DBG(ndpi_struct, "http_stage %d dir %d req/res %d/%d\n",
	       flow->l4.tcp.http_stage, packet->packet_direction,
	       is_request(ndpi_struct, flow), is_response(ndpi_struct, flow));

  if(flow->l4.tcp.http_stage == 0) { /* Start: waiting for (the beginning of) a request */
    filename_start = is_request(ndpi_struct, flow);
    if(filename_start == 0) {
      /* Flow starting with a response? */
      if(is_response(ndpi_struct, flow)) {
        NDPI_LOG_DBG2(ndpi_struct, "Response where a request were expected\n");
	/* This is tricky. Two opposing goals:
	   1) We want to correctly match request with response!! -> Skip this response
	      and keep looking for a request.
	   2) We want to support asymmetric detection
	   Trade-off:
	   a) set HTTP as master (it is a guess; we can't know it from the reply only)
	   b) process the response(s) and save the metadata
	   c) look for a request. If we found it, reset everything (master,
	      classification and metadata!) */
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
        process_response(ndpi_struct, flow);

	flow->l4.tcp.http_stage = packet->packet_direction + 3; // packet_direction 0: stage 3, packet_direction 1: stage 4
        return;
      }
      /* The first pkt is neither a request nor a response -> no http */
      NDPI_LOG_DBG2(ndpi_struct, "Neither req nor response -> exclude\n");
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
    NDPI_LOG_DBG2(ndpi_struct, "Request where expected\n");

    process_request(ndpi_struct, flow, filename_start);

    /* Wait for the response */
    flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2

    return;
  } else if(flow->l4.tcp.http_stage == 1 || flow->l4.tcp.http_stage == 2) {
    /* Found a request, looking for the response */

    if(flow->l4.tcp.http_stage - packet->packet_direction == 1) {
      /* Another pkt from the same direction (probably another fragment of the request)
         Keep lookng for the response */
      NDPI_LOG_DBG2(ndpi_struct, "Another piece of request\n");
      filename_start = is_request(ndpi_struct, flow);
      if(filename_start > 0) {
        /* Probably a new, separated request (asymmetric flow or missing pkts?).
	   What should we do? We definitely don't want to mix data from different
	   requests. The easiest (but costly) idea is to reset the state and
	   process it (i.e. we keep the metadata of the last request that we
	   have processed) */
        reset(ndpi_struct, flow);
        process_request(ndpi_struct, flow, filename_start);
	return;
      }
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      check_content_type_and_change_protocol(ndpi_struct, flow);
      return;
    } else if(is_response(ndpi_struct, flow)) {
      NDPI_LOG_DBG2(ndpi_struct, "Response where expected\n");

      process_response(ndpi_struct, flow);

      flow->l4.tcp.http_stage = 0;
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "The msg from the server doesn't look like a response...\n");
      /* TODO */
    }
  } else if(flow->l4.tcp.http_stage == 3 || flow->l4.tcp.http_stage == 4) {
    /* Found a response but we want a request */

    if(flow->l4.tcp.http_stage - packet->packet_direction == 3) {
      /* Another pkt from the same direction (probably another fragment of the response)
         Keep lookng for the request */
      NDPI_LOG_DBG2(ndpi_struct, "Another piece of response\n");
      if(is_response(ndpi_struct, flow)) {
        /* See the comment above about how we handle consecutive requests/responses */
        reset(ndpi_struct, flow);
        process_response(ndpi_struct, flow);
	return;
      }
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      check_content_type_and_change_protocol(ndpi_struct, flow);
      return;
    }

    NDPI_LOG_DBG2(ndpi_struct, "Found a request. We need to reset the state!\n");

    reset(ndpi_struct, flow);
    flow->l4.tcp.http_stage = 0;
    return ndpi_check_http_tcp(ndpi_struct, flow);
  }
}

/* ********************************* */

static void ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  /* Break after 20 packets. */
  if(flow->packet_counter > 20) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  NDPI_LOG_DBG(ndpi_struct, "search HTTP\n");
  ndpi_check_http_tcp(ndpi_struct, flow);

  if(flow->host_server_name[0] != '\0'&&
     flow->http.response_status_code != 0) {
    flow->extra_packets_func = NULL; /* We're good now */

    if(flow->initial_binary_bytes_len) ndpi_analyze_content_signature(ndpi_struct, flow);
  }
}

/* ********************************* */

ndpi_http_method ndpi_get_http_method(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow) {
  if(!flow) {
    return(NDPI_HTTP_METHOD_UNKNOWN);
  } else
    return(flow->http.method);
}

/* ********************************* */

char* ndpi_get_http_url(struct ndpi_detection_module_struct *ndpi_struct,
			struct ndpi_flow_struct *flow) {
  if((!flow) || (!flow->http.url))
    return("");
  else
    return(flow->http.url);
}

/* ********************************* */

char* ndpi_get_http_content_type(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  if((!flow) || (!flow->http.content_type))
    return("");
  else
    return(flow->http.content_type);
}


void init_http_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("HTTP",ndpi_struct, *id,
				      NDPI_PROTOCOL_HTTP,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
