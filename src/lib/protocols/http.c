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

static void ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
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

  ndpi_search_http_tcp(ndpi_struct, flow);

#ifdef HTTP_DEBUG
  printf("=> %s()\n", __FUNCTION__);
#endif

  if((flow->host_server_name[0] != '\0')
     && (flow->http.response_status_code != 0)
     ) {
    /* stop extra processing */
    if(flow->initial_binary_bytes_len) ndpi_analyze_content_signature(ndpi_struct, flow);

    flow->extra_packets_func = NULL; /* We're good now */
    return(0);
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
		return(flow->category);
	      }
	    }
	  }
	}

	ndpi_validate_http_content(ndpi_struct, flow);
      }
    }

    /* check for attachment */
    if(packet->content_disposition_line.len > 0) {
      u_int8_t attachment_len = sizeof("attachment; filename");

      if(packet->content_disposition_line.len > attachment_len) {
	u_int8_t filename_len = packet->content_disposition_line.len - attachment_len;
	int i;

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
					 u_int16_t http_protocol,
					 ndpi_protocol_category_t category) {
  u_int16_t master_protocol;

#ifdef HTTP_DEBUG
  printf("=> %s()\n", __FUNCTION__);
#endif

  if(flow->extra_packets_func && (flow->guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN))
     return; /* Nothing new to add */

  /* If no custom protocol has been detected */
  if((flow->guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN)
     || ((http_protocol != NDPI_PROTOCOL_HTTP) &&
         (http_protocol != NDPI_PROTOCOL_HTTP_CONNECT) &&
         (http_protocol != NDPI_PROTOCOL_HTTP_PROXY))
     )
    flow->guessed_host_protocol_id = http_protocol;

  // ndpi_int_reset_protocol(flow);
  master_protocol = NDPI_PROTOCOL_HTTP;
  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN)
    master_protocol = flow->detected_protocol_stack[1];
  else if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP_CONNECT ||
          flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP_PROXY)
    master_protocol = flow->detected_protocol_stack[0];

  /* Update the classification only if we don't already have master + app;
     for example don't change the protocols if we have already detected a
     sub-protocol via the (content-matched) subprotocols logic (i.e.
     MPEGDASH, SOAP, ....) */
  if(flow->detected_protocol_stack[1] == 0)
    ndpi_set_detected_protocol(ndpi_struct, flow, flow->guessed_host_protocol_id,
			       master_protocol,
			       NDPI_CONFIDENCE_DPI);

  flow->max_extra_packets_to_check = 8;
  flow->extra_packets_func = ndpi_search_http_tcp_again;
  flow->http_detected = 1;

  switch(flow->detected_protocol_stack[1]) {
  case NDPI_PROTOCOL_HTTP_CONNECT:
  case NDPI_PROTOCOL_HTTP_PROXY:
    if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP) {
      flow->detected_protocol_stack[0] = flow->detected_protocol_stack[1];
      flow->detected_protocol_stack[1] = NDPI_PROTOCOL_UNKNOWN;
    }
    break;
  }
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
				 struct ndpi_flow_struct *flow) {
  if((flow->l4.tcp.http_stage == 0) || (flow->http.url && flow->http_detected)) {
    char *double_col = strchr((char*)flow->host_server_name, ':');

    if(double_col) double_col[0] = '\0';

    if(ndpi_match_hostname_protocol(ndpi_struct, flow,
				    flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN ? flow->detected_protocol_stack[1] : NDPI_PROTOCOL_HTTP,
				    flow->host_server_name,
				    strlen(flow->host_server_name)) == 0) {
      if(flow->http.url &&
         ((strstr(flow->http.url, ":8080/downloading?n=0.") != NULL)
          || (strstr(flow->http.url, ":8080/upload?n=0.") != NULL))) {
	/* This looks like Ookla speedtest */
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
      }
    }

    if (flow->http.url != NULL &&
        strstr(flow->http.url, "micloud.xiaomi.net") != NULL)
    {
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_XIAOMI, NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
    }
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
  if((strstr(ua, "+http") != NULL)
     || (strstr(ua, " http") != NULL)
     || ndpi_strncasestr(ua, "Crawler", ua_len)
     || ndpi_strncasestr(ua, "Bot", ua_len) /* bot/robot */
     ) {
    char str[64];

    snprintf(str, sizeof(str), "UA %s", ua);

    ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_CRAWLER_BOT, str);
  }
}

/* ************************************************************* */

int http_process_user_agent(struct ndpi_detection_module_struct *ndpi_struct,
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

  if (ndpi_user_agent_set(flow, ua_ptr, ua_ptr_len) != NULL)
  {
    ndpi_check_user_agent(ndpi_struct, flow, flow->http.user_agent, ua_ptr_len);
  } else {
    NDPI_LOG_DBG2(ndpi_struct, "Could not set HTTP user agent\n");
  }

  NDPI_LOG_DBG2(ndpi_struct, "User Agent Type line found %.*s\n",
		ua_ptr_len, ua_ptr);
  return 0;
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
    ndpi_set_risk(ndpi_struct, flow, NDPI_HTTP_NUMERIC_IP_HOST, str);
  }
}

/* ************************************************************* */

static void ndpi_check_http_url(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				char *url) {
  /* Nothing to do */
}

/* ************************************************************* */

/**
   NOTE
   ndpi_parse_packet_line_info is in ndpi_main.c
*/
static void check_content_type_and_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int ret;

  if(flow->http_detected && (flow->http.response_status_code != 0))
    return;

  if((flow->http.url == NULL)
     && (packet->http_url_name.len > 0)
     && (packet->host_line.len > 0)) {
    int len = packet->http_url_name.len + packet->host_line.len + 1;

    if(isdigit(packet->host_line.ptr[0])
       && (packet->host_line.len < 21))
      ndpi_check_numeric_ip(ndpi_struct, flow, (char*)packet->host_line.ptr, packet->host_line.len);

    flow->http.url = ndpi_malloc(len);
    if(flow->http.url) {
      u_int offset = 0;

      if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP_CONNECT) {
	strncpy(flow->http.url, (char*)packet->http_url_name.ptr,
		packet->http_url_name.len);

	flow->http.url[packet->http_url_name.len] = '\0';
      } else {
	/* Check if we pass through a proxy (usually there is also the Via: ... header) */
	if(strncmp((char*)packet->http_url_name.ptr, "http://", 7) != 0)
	  strncpy(flow->http.url, (char*)packet->host_line.ptr, offset = packet->host_line.len);

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

      ndpi_check_http_url(ndpi_struct, flow, &flow->http.url[packet->host_line.len]);
    }

    flow->http.method = ndpi_http_str2method((const char*)packet->http_method.ptr,
					     (u_int16_t)packet->http_method.len);

    if((flow->http.method == NDPI_HTTP_METHOD_RPC_IN_DATA)
       || (flow->http.method == NDPI_HTTP_METHOD_RPC_OUT_DATA)) {
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RPC, flow->detected_protocol_stack[0], NDPI_CONFIDENCE_DPI);
      check_content_type_and_change_protocol(ndpi_struct, flow);
    }
  }

  if(packet->server_line.ptr != NULL && (packet->server_line.len > 7)) {
    if(strncmp((const char *)packet->server_line.ptr, "ntopng ", 7) == 0) {
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NTOP, NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
      NDPI_CLR_BIT(flow->risk, NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT);
    }
  }

  if(packet->user_agent_line.ptr != NULL && packet->user_agent_line.len != 0) {
    ret = http_process_user_agent(ndpi_struct, flow, packet->user_agent_line.ptr, packet->user_agent_line.len);
    /* TODO: Is it correct to avoid setting ua, host_name,... if we have a (Netflix) subclassification? */
    if(ret != 0)
      return;
  }

  /* check for host line */
  if(packet->host_line.ptr != NULL) {
    u_int len;

    NDPI_LOG_DBG2(ndpi_struct, "HOST line found %.*s\n",
		  packet->host_line.len, packet->host_line.ptr);

    /* Copy result for nDPI apps */
    ndpi_hostname_sni_set(flow, packet->host_line.ptr, packet->host_line.len);

    if(strlen(flow->host_server_name) > 0) {
      ndpi_check_dga_name(ndpi_struct, flow, flow->host_server_name, 1);

      if(ndpi_is_valid_hostname(flow->host_server_name,
				strlen(flow->host_server_name)) == 0) {
	char str[128];

	snprintf(str, sizeof(str), "Invalid host %s", flow->host_server_name);
	ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, str);

	/* This looks like an attack */
	ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, NULL);
      }
    }

    if(packet->forwarded_line.ptr) {
      if(flow->http.nat_ip == NULL) {
        len = packet->forwarded_line.len;
        flow->http.nat_ip = ndpi_malloc(len + 1);
        if(flow->http.nat_ip != NULL) {
          strncpy(flow->http.nat_ip, (char*)packet->forwarded_line.ptr, len);
          flow->http.nat_ip[len] = '\0';
        }
      }
    }

    ndpi_http_parse_subprotocol(ndpi_struct, flow);

    /**
       check result of host subprotocol detection

       if "detected" in flow == 0 then "detected" = "guess"
       else "guess" = "detected"
    **/
    if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
      /* Avoid putting as subprotocol a "core" protocol such as SSL or DNS */
      if(ndpi_struct->proto_defaults[flow->guessed_protocol_id].subprotocol_count == 0) {
	if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN &&
	   flow->guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
	  flow->detected_protocol_stack[0] = flow->guessed_host_protocol_id;
	  flow->detected_protocol_stack[1] = flow->guessed_protocol_id;
        }
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

    if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN) {
      if((flow->detected_protocol_stack[1] != NDPI_PROTOCOL_HTTP)
	 && (flow->detected_protocol_stack[1] != NDPI_PROTOCOL_HTTP_CONNECT)
	 && (flow->detected_protocol_stack[1] != NDPI_PROTOCOL_HTTP_PROXY)) {
	NDPI_LOG_INFO(ndpi_struct, "found HTTP/%s\n",
		      ndpi_get_proto_name(ndpi_struct, flow->detected_protocol_stack[0]));
	ndpi_int_http_add_connection(ndpi_struct, flow, flow->detected_protocol_stack[0], NDPI_PROTOCOL_CATEGORY_WEB);
	return; /* We have identified a sub-protocol so we're done */
      }
    }
  }

  if(flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN)
    flow->guessed_protocol_id = NDPI_PROTOCOL_HTTP;

  /* check for accept line */
  if(packet->accept_line.ptr != NULL) {
    NDPI_LOG_DBG2(ndpi_struct, "Accept line found %.*s\n",
		  packet->accept_line.len, packet->accept_line.ptr);
  }

  /* check for authorization line */
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

  if(packet->content_line.ptr != NULL && packet->content_line.len != 0) {
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

    if(flow->http_detected && packet->content_line.ptr && *(char*)packet->content_line.ptr) {
      /* Matching on Content-Type.
          OCSP:  application/ocsp-request, application/ocsp-response
       */
      if(strncmp((const char *)packet->content_line.ptr, "application/ocsp-", 17) == 0) {
        NDPI_LOG_DBG2(ndpi_struct, "Found OCSP\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OCSP, NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
      }
    }
  }

  if(packet->user_agent_line.ptr != NULL && packet->user_agent_line.len != 0 &&
     flow->http.url) {
    /* WindowsUpdate over some kind of CDN */
    if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN &&
       flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP &&
       (strstr(flow->http.url, "delivery.mp.microsoft.com/") ||
        strstr(flow->http.url, "download.windowsupdate.com/")) &&
       ndpi_strnstr((const char *)packet->user_agent_line.ptr, "Microsoft-Delivery-Optimization/",
                    packet->user_agent_line.len) &&
       ndpi_isset_risk(ndpi_struct, flow, NDPI_HTTP_NUMERIC_IP_HOST)) {
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WINDOWS_UPDATE, NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
    }
  }

  if(ndpi_get_http_method(ndpi_struct, flow) != NDPI_HTTP_METHOD_UNKNOWN) {
    ndpi_int_http_add_connection(ndpi_struct, flow, flow->detected_protocol_stack[0], NDPI_PROTOCOL_CATEGORY_WEB);
  }
}

/* ************************************************************* */

static void check_http_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  /* Add here your payload code check */
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

static void http_bitmask_exclude_other(struct ndpi_flow_struct *flow)
{
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_XBOX);
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

static int is_a_suspicious_header(const char* suspicious_headers[], struct ndpi_int_one_line_struct packet_line){
  int i;
  unsigned int header_len;
  const u_int8_t* header_limit;

  if((header_limit = memchr(packet_line.ptr, ':', packet_line.len))) {
    header_len = header_limit - packet_line.ptr;
    for(i=0; suspicious_headers[i] != NULL; i++){
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
    switch(packet->line[i].ptr[0]){
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

/*************************************************************************************************/

static void ndpi_check_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t filename_start; /* the filename in the request method line, e.g., "GET filename_start..."*/

  packet->packet_lines_parsed_complete = 0;

  if(packet->http_check_content && (packet->payload_packet_len > 0)) {
    ndpi_http_check_human_redeable_content(ndpi_struct, flow, packet->payload, packet->payload_packet_len);
    packet->http_check_content = 0; /* One packet is enough */
  }

  /* Check if we so far detected the protocol in the request or not. */
  if((packet->payload_packet_len > 0) /* Needed in case of extra packet processing */
     && (flow->l4.tcp.http_stage == 0)) {
    /* Expected a request */
    flow->http_detected = 0;

    NDPI_LOG_DBG2(ndpi_struct, "HTTP stage %d: \n", flow->l4.tcp.http_stage);

    filename_start = http_request_url_offset(ndpi_struct, flow);

    if(filename_start == 0) { /* not a regular request. In the HTTP first stage, may be a truncated flow or other protocols */
      NDPI_LOG_DBG2(ndpi_struct, "Filename HTTP not found, we look for possible truncate flow..\n");

      if(packet->payload_packet_len >= 7 && strncasecmp((const char *)packet->payload, "HTTP/1.", 7) == 0) {
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
	  else if(flow->http.response_status_code >= 400) {
	    char ec[48];
	    
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

	    snprintf(ec, sizeof(ec), "HTTP Error Code %u", flow->http.response_status_code);
	    ndpi_set_risk(ndpi_struct, flow, NDPI_ERROR_CODE_DETECTED, ec);
	  }
	}

	ndpi_parse_packet_line_info(ndpi_struct, flow);
        check_content_type_and_change_protocol(ndpi_struct, flow);
	ndpi_validate_http_content(ndpi_struct, flow);
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP, NDPI_PROTOCOL_CATEGORY_WEB);
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

	if(ndpi_struct->ookla_cache != NULL) {
	  if(packet->iph != NULL) {
	    if(packet->tcp->source == htons(8080))
	      ndpi_lru_add_to_cache(ndpi_struct->ookla_cache, packet->iph->saddr, 1 /* dummy */);
	    else
	      ndpi_lru_add_to_cache(ndpi_struct->ookla_cache, packet->iph->daddr, 1 /* dummy */);
	  } else if(packet->iphv6 != NULL) {
	    u_int32_t h;

	    if(packet->tcp->source == htons(8080))
	      h = ndpi_quick_hash((unsigned char *)&packet->iphv6->ip6_src, sizeof(packet->iphv6->ip6_src));
	    else
	      h = ndpi_quick_hash((unsigned char *)&packet->iphv6->ip6_dst, sizeof(packet->iphv6->ip6_dst));

	    ndpi_lru_add_to_cache(ndpi_struct->ookla_cache, h, 1 /* dummy */);
	  }
	}

        return;
      }

      /* try to get some additional request header info even if the packet may not be HTTP */
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      if(packet->http_num_headers > 0) {
        check_content_type_and_change_protocol(ndpi_struct, flow);
        return;
      }

      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      http_bitmask_exclude_other(flow);
      return;
    } else {
      /* This check is required as RTSP is pretty similiar to HTTP (prevent false-positives). */
      if (strncasecmp((const char *)packet->payload + filename_start,
                      "rtsp://", ndpi_min(7, packet->payload_packet_len - filename_start)) == 0)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      } else {
        ndpi_int_http_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP, NDPI_PROTOCOL_CATEGORY_WEB);
      }
    }

    NDPI_LOG_DBG2(ndpi_struct,
		  "Filename HTTP found: %d, we look for line info..\n", filename_start);

    ndpi_parse_packet_line_info(ndpi_struct, flow);
    ndpi_check_http_header(ndpi_struct, flow);

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
       && strncasecmp((const char *)&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
      /* Request line complete. Ex. "GET / HTTP/1.1" */

      packet->http_url_name.ptr = &packet->payload[filename_start];
      packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

      packet->http_method.ptr = packet->line[0].ptr;
      packet->http_method.len = filename_start - 1;

      // Set the HTTP requested version: 0=HTTP/1.0 and 1=HTTP/1.1
      if(memcmp(&packet->line[0].ptr[packet->line[0].len - 1], "1", 1) == 0)
	flow->http.request_version = 1;
      else
	flow->http.request_version = 0;

      /* Check for Ookla */
      if((packet->referer_line.len > 0)
	 && ndpi_strnstr((const char *)packet->referer_line.ptr, "www.speedtest.net", packet->referer_line.len)) {
	goto ookla_found;
      }

      if((packet->http_url_name.len > 7)
	 && (!strncasecmp((const char*) packet->http_url_name.ptr, "http://", 7))) {
        NDPI_LOG_INFO(ndpi_struct, "found HTTP_PROXY\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_HTTP_PROXY, NDPI_CONFIDENCE_DPI);
        check_content_type_and_change_protocol(ndpi_struct, flow);
	flow->http_detected = 1;
	flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
	return;
      }

      if(filename_start == 8 && (strncasecmp((const char *)packet->payload, "CONNECT ", 8) == 0)) {
        NDPI_LOG_INFO(ndpi_struct, "found HTTP_CONNECT\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_HTTP_CONNECT, NDPI_CONFIDENCE_DPI);
        check_content_type_and_change_protocol(ndpi_struct, flow);
	flow->http_detected = 1;
	flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
	return;
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

	/* if(!flow->http_detected) */ {
	  u_int proto = flow->detected_protocol_stack[1] ? flow->detected_protocol_stack[1] : flow->detected_protocol_stack[0];

	  if(proto == NDPI_PROTOCOL_UNKNOWN) proto = NDPI_PROTOCOL_HTTP;
	  ndpi_int_http_add_connection(ndpi_struct, flow, proto, NDPI_PROTOCOL_CATEGORY_WEB);
	  flow->http_detected = 1;
	  NDPI_LOG_DBG2(ndpi_struct,
			"HTTP START Found, we will look further for the response...\n");
	  flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
	  check_content_type_and_change_protocol(ndpi_struct, flow);
	}
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
	 && strncasecmp((const char *)&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {

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

    /* Parse packet line and we look for the subprotocols */
    ndpi_parse_packet_line_info(ndpi_struct, flow);
    check_content_type_and_change_protocol(ndpi_struct, flow);

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

ndpi_http_method ndpi_get_http_method(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow) {
  if(!flow) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, (char*)"Unknown HTTP Method");
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


void init_http_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("HTTP",ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_HTTP,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
