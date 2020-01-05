/*
 * directdownloadlink.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK

#include "ndpi_api.h"


#ifdef NDPI_DEBUG_DIRECT_DOWNLOAD_LINK
//#define NDPI_DEBUG_DIRECT_DOWNLOAD_LINK_NOTHING_FOUND
//#define NDPI_DEBUG_DIRECT_DOWNLOAD_LINK_PACKET_TOO_SMALL
#define NDPI_DEBUG_DIRECT_DOWNLOAD_LINK_IP
#endif

static void ndpi_int_direct_download_link_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
							 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK, NDPI_PROTOCOL_UNKNOWN);

  flow->l4.tcp.ddlink_server_direction = packet->packet_direction;
}



/*
  return 0 if nothing has been detected
  return 1 if it is a megaupload packet
*/
u_int8_t search_ddl_domains(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t filename_start = 0;
  u_int16_t i = 1;
  u_int16_t host_line_len_without_port;

  if (packet->payload_packet_len < 100) {
    NDPI_LOG_DBG2(ndpi_struct, "DDL: Packet too small\n");
    goto end_ddl_nothing_found;
  }



  if (memcmp(packet->payload, "POST ", 5) == 0) {
    filename_start = 5;		// POST
    NDPI_LOG_DBG2(ndpi_struct, "DDL: POST FOUND\n");
  } else if (memcmp(packet->payload, "GET ", 4) == 0) {
    filename_start = 4;		// GET
    NDPI_LOG_DBG2(ndpi_struct, "DDL: GET FOUND\n");
  } else {
    goto end_ddl_nothing_found;
  }
  // parse packet
  ndpi_parse_packet_line_info(ndpi_struct, flow);

  if (packet->host_line.ptr == NULL) {
    NDPI_LOG_DBG2(ndpi_struct, "DDL: NO HOST FOUND\n");
    goto end_ddl_nothing_found;
  }

  NDPI_LOG_DBG2(ndpi_struct, "DDL: Host: found\n");

  if (packet->line[0].len < 9 + filename_start
      || memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) != 0) {
    NDPI_LOG_DBG2(ndpi_struct, "DDL: PACKET NOT HTTP CONFORM.\nXXX%.*sXXX\n",
	     8, &packet->line[0].ptr[packet->line[0].len - 9]);
    goto end_ddl_nothing_found;
  }
  // BEGIN OF AUTOMATED CODE GENERATION
  // first see if we have ':port' at the end of the line
  host_line_len_without_port = packet->host_line.len;
  if (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] >= '0'
      && packet->host_line.ptr[packet->host_line.len - i] <= '9') {
    i = 2;
    while (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] >= '0'
	   && packet->host_line.ptr[host_line_len_without_port - i] <= '9') {
      NDPI_LOG_DBG2(ndpi_struct, "DDL: number found\n");
      i++;
    }
    if (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] == ':') {
      NDPI_LOG_DBG2(ndpi_struct, "DDL: ':' found\n");
      host_line_len_without_port = host_line_len_without_port - i;
    }
  }
  // then start automated code generation

  if (host_line_len_without_port >= 0 + 4
      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 4], ".com", 4) == 0) {
    if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'd') {
      if (host_line_len_without_port >= 5 + 6 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 6], "4share", 6) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 8 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "fileclou", 8) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 5
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "uploa", 5) == 0) {
	if (host_line_len_without_port >= 10 + 6 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 6], "files-", 6) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 10 - 6 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 10 - 6 - 1] == '.')) {
	  goto end_ddl_found;
	}
	if (host_line_len_without_port >= 10 + 4 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4], "mega", 4) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == '.')) {
	  goto end_ddl_found;
	}
	if (host_line_len_without_port >= 10 + 5 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 5], "rapid", 5) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == '.')) {
	  goto end_ddl_found;
	}
	if (host_line_len_without_port >= 10 + 5 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 5], "turbo", 5) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == '.')) {
	  goto end_ddl_found;
	}
	goto end_ddl_nothing_found;
      }
      goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'o') {
      if (host_line_len_without_port >= 5 + 6 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 6], "badong", 6) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 5 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "fileh", 5) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'g') {
      if (host_line_len_without_port >= 5 + 2
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 2], "in", 2) == 0) {
	if (host_line_len_without_port >= 7 + 4
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 7 - 4], "shar", 4) == 0) {
	  if (host_line_len_without_port >= 11 + 4 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 11 - 4], "best", 4) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 11 - 4 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 11 - 4 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  if (host_line_len_without_port >= 11 + 5 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 11 - 5], "quick", 5) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 11 - 5 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 11 - 5 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  goto end_ddl_nothing_found;
	}
	if (host_line_len_without_port >= 7 + 6 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 7 - 6], "upload", 6) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 7 - 6 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 7 - 6 - 1] == '.')) {
	  goto end_ddl_found;
	}
	goto end_ddl_nothing_found;
      }
      if (host_line_len_without_port >= 5 + 7 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 7], "sharebi", 7) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 4 + 8 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 8], "bigfilez", 8) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 4 - 8 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 4 - 8 - 1] == '.')) {
      goto end_ddl_found;
    }
    if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'e') {
      if (host_line_len_without_port >= 5 + 3
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 3], "fil", 3) == 0) {
	if (host_line_len_without_port >= 8 + 2
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 2], "mo", 2) == 0) {
	  if (host_line_len_without_port >= 10 + 5 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 5], "china", 5) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  if (host_line_len_without_port >= 8 + 2 + 1
	      && (packet->host_line.ptr[host_line_len_without_port - 8 - 2 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 8 - 2 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	}
	if (host_line_len_without_port >= 8 + 3 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 3], "hot", 3) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 8 - 3 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 8 - 3 - 1] == '.')) {
	  goto end_ddl_found;
	}
	if (host_line_len_without_port >= 8 + 6 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 6], "keepmy", 6) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 8 - 6 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 8 - 6 - 1] == '.')) {
	  goto end_ddl_found;
	}
	if (host_line_len_without_port >= 8 + 1
	    && packet->host_line.ptr[host_line_len_without_port - 8 - 1] == 'e') {
	  if (host_line_len_without_port >= 9 + 3 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 3], "sav", 3) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 9 - 3 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 9 - 3 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  if (host_line_len_without_port >= 9 + 5 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 5], "sendm", 5) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 9 - 5 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 9 - 5 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  goto end_ddl_nothing_found;
	}
	if (host_line_len_without_port >= 8 + 8 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 8], "sharebig", 8) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 8 - 8 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 8 - 8 - 1] == '.')) {
	  goto end_ddl_found;
	}
	if (host_line_len_without_port >= 8 + 3 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 3], "up-", 3) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 8 - 3 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 8 - 3 - 1] == '.')) {
	  goto end_ddl_found;
	}
	goto end_ddl_nothing_found;
      }
      if (host_line_len_without_port >= 5 + 1 && packet->host_line.ptr[host_line_len_without_port - 5 - 1] == 'r') {
	if (host_line_len_without_port >= 6 + 3
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 6 - 3], "sha", 3) == 0) {
	  if (host_line_len_without_port >= 9 + 1
	      && packet->host_line.ptr[host_line_len_without_port - 9 - 1] == '-') {
	    if (host_line_len_without_port >= 10 + 4 + 1
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4], "easy",
			  4) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
				      || packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] ==
				      '.')) {
	      goto end_ddl_found;
	    }
	    if (host_line_len_without_port >= 10 + 4 + 1
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4], "fast",
			  4) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
				      || packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] ==
				      '.')) {
	      goto end_ddl_found;
	    }
	    if (host_line_len_without_port >= 10 + 4 + 1
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4], "live",
			  4) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
				      || packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] ==
				      '.')) {
	      goto end_ddl_found;
	    }
	    goto end_ddl_nothing_found;
	  }
	  if (host_line_len_without_port >= 9 + 4 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 4], "ftp2", 4) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  if (host_line_len_without_port >= 9 + 4 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 4], "gige", 4) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  if (host_line_len_without_port >= 9 + 4 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 4], "mega", 4) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  if (host_line_len_without_port >= 9 + 5 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 5], "rapid", 5) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 9 - 5 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 9 - 5 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  goto end_ddl_nothing_found;
	}
	if (host_line_len_without_port >= 6 + 7 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 6 - 7], "mediafi", 7) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 6 - 7 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 6 - 7 - 1] == '.')) {
	  goto end_ddl_found;
	}
	goto end_ddl_nothing_found;
      }
      if (host_line_len_without_port >= 5 + 7 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 7], "gigasiz", 7) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 8 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "sendspac", 8) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 7 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 7], "sharebe", 7) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 11 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 11], "sharebigfli", 11) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 11 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 11 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 8 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "fileserv", 8) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 's') {
      if (host_line_len_without_port >= 5 + 1 && packet->host_line.ptr[host_line_len_without_port - 5 - 1] == 'e') {
	if (host_line_len_without_port >= 6 + 10 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 6 - 10], "depositfil",
		      10) == 0 && (packet->host_line.ptr[host_line_len_without_port - 6 - 10 - 1] == ' '
				   || packet->host_line.ptr[host_line_len_without_port - 6 - 10 - 1] == '.')) {
	  goto end_ddl_found;
	}
	if (host_line_len_without_port >= 6 + 8 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 6 - 8], "megashar", 8) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 6 - 8 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 6 - 8 - 1] == '.')) {
	  goto end_ddl_found;
	}
	goto end_ddl_nothing_found;
      }
      if (host_line_len_without_port >= 5 + 10 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 10], "fileupyour", 10) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 4 + 11 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 11], "filefactory", 11) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 4 - 11 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 4 - 11 - 1] == '.')) {
      goto end_ddl_found;
    }
    if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 't') {
      if (host_line_len_without_port >= 5 + 8 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "filefron", 8) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 10 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 10], "uploadingi", 10) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 11 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 11], "yourfilehos", 11) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 11 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 11 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'r') {
      if (host_line_len_without_port >= 5 + 8 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "mytempdi", 8) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 10 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 10], "uploadpowe", 10) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 4 + 9 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 9], "mega.1280", 9) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == '.')) {
      goto end_ddl_found;
    }
    if (host_line_len_without_port >= 4 + 9 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 9], "filesonic", 9) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == '.')) {
      goto end_ddl_found;
    }
    goto end_ddl_nothing_found;
  }
  if (host_line_len_without_port >= 0 + 4
      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 4], ".net", 4) == 0) {
    if (host_line_len_without_port >= 4 + 7 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 7], "badongo", 7) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == '.')) {
      goto end_ddl_found;
    }
    if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'd') {
      if (host_line_len_without_port >= 5 + 3
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 3], "loa", 3) == 0) {
	if (host_line_len_without_port >= 8 + 5 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 5], "fast-", 5) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == '.')) {
	  goto end_ddl_found;
	}
	if (host_line_len_without_port >= 8 + 2
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 2], "up", 2) == 0) {
	  if (host_line_len_without_port >= 10 + 5 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 5], "file-", 5) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  if (host_line_len_without_port >= 10 + 6 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 6], "simple",
			6) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 6 - 1] == ' '
				    || packet->host_line.ptr[host_line_len_without_port - 10 - 6 - 1] ==
				    '.')) {
	    goto end_ddl_found;
	  }
	  if (host_line_len_without_port >= 10 + 3 + 1
	      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 3], "wii", 3) == 0
	      && (packet->host_line.ptr[host_line_len_without_port - 10 - 3 - 1] == ' '
		  || packet->host_line.ptr[host_line_len_without_port - 10 - 3 - 1] == '.')) {
	    goto end_ddl_found;
	  }
	  goto end_ddl_nothing_found;
	}
	goto end_ddl_nothing_found;
      }
      if (host_line_len_without_port >= 5 + 7 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 7], "filesen", 7) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 4 + 5 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 5], "filer", 5) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 4 - 5 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 4 - 5 - 1] == '.')) {
      goto end_ddl_found;
    }
    if (host_line_len_without_port >= 4 + 9 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 9], "livedepot", 9) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == '.')) {
      goto end_ddl_found;
    }
    if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'e') {
      if (host_line_len_without_port >= 5 + 5 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "mofil", 5) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 17 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 17], "odsiebie.najlepsz",
		    17) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 17 - 1] == ' '
				 || packet->host_line.ptr[host_line_len_without_port - 5 - 17 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 5 + 5 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "zshar", 5) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    goto end_ddl_nothing_found;
  }
  if (host_line_len_without_port >= 0 + 1 && packet->host_line.ptr[host_line_len_without_port - 0 - 1] == 'u') {
    if (host_line_len_without_port >= 1 + 6 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 6], "data.h", 6) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 1 - 6 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 1 - 6 - 1] == '.')) {
      goto end_ddl_found;
    }
    if (host_line_len_without_port >= 1 + 2
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 2], ".r", 2) == 0) {
      if (host_line_len_without_port >= 3 + 10 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 10], "filearchiv", 10) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 3 - 10 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 3 - 10 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 3 + 8 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 8], "filepost", 8) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 3 - 8 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 3 - 8 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 3 + 7 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 7], "ifolder", 7) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 3 - 7 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 3 - 7 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    goto end_ddl_nothing_found;
  }
  if (host_line_len_without_port >= 0 + 11 + 1
      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 11], "filehost.tv", 11) == 0
      && (packet->host_line.ptr[host_line_len_without_port - 0 - 11 - 1] == ' '
	  || packet->host_line.ptr[host_line_len_without_port - 0 - 11 - 1] == '.')) {
    goto end_ddl_found;
  }
  if (host_line_len_without_port >= 0 + 3
      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 3], ".to", 3) == 0) {
    if (host_line_len_without_port >= 3 + 1 && packet->host_line.ptr[host_line_len_without_port - 3 - 1] == 'e') {
      if (host_line_len_without_port >= 4 + 7 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 7], "filesaf", 7) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 4 + 8 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 8], "sharebas", 8) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 4 - 8 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 4 - 8 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 3 + 5 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 5], "files", 5) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 3 - 5 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 3 - 5 - 1] == '.')) {
      goto end_ddl_found;
    }
    if (host_line_len_without_port >= 3 + 1 && packet->host_line.ptr[host_line_len_without_port - 3 - 1] == 'd') {
      if (host_line_len_without_port >= 4 + 3
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 3], "loa", 3) == 0) {
	if (host_line_len_without_port >= 7 + 7 + 1
	    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 7 - 7], "file-up", 7) == 0
	    && (packet->host_line.ptr[host_line_len_without_port - 7 - 7 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 7 - 7 - 1] == '.')) {
	  goto end_ddl_found;
	}
	if (host_line_len_without_port >= 4 + 3 + 1
	    && (packet->host_line.ptr[host_line_len_without_port - 4 - 3 - 1] == ' '
		|| packet->host_line.ptr[host_line_len_without_port - 4 - 3 - 1] == '.')) {
	  goto end_ddl_found;
	}
      }
      if (host_line_len_without_port >= 4 + 7 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 7], "uploade", 7) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    goto end_ddl_nothing_found;
  }
  if (host_line_len_without_port >= 0 + 1 && packet->host_line.ptr[host_line_len_without_port - 0 - 1] == 'z') {
    if (host_line_len_without_port >= 1 + 14 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 14], "leteckaposta.c", 14) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 1 - 14 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 1 - 14 - 1] == '.')) {
      goto end_ddl_found;
    }
    if (host_line_len_without_port >= 1 + 12 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 12], "yourfiles.bi", 12) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 1 - 12 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 1 - 12 - 1] == '.')) {
      goto end_ddl_found;
    }
    goto end_ddl_nothing_found;
  }
  if (host_line_len_without_port >= 0 + 1 && packet->host_line.ptr[host_line_len_without_port - 0 - 1] == 'n') {
    if (host_line_len_without_port >= 1 + 9 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 9], "netload.i", 9) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 1 - 9 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 1 - 9 - 1] == '.')) {
      goto end_ddl_found;
    }
    if (host_line_len_without_port >= 1 + 2
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 2], ".v", 2) == 0) {
      if (host_line_len_without_port >= 3 + 7 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 7], "4shared", 7) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 3 - 7 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 3 - 7 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 3 + 9 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 9], "megashare", 9) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 3 - 9 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 3 - 9 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    goto end_ddl_nothing_found;
  }
  if (host_line_len_without_port >= 0 + 3
      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 3], ".de", 3) == 0) {
    if (host_line_len_without_port >= 3 + 5
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 5], "share", 5) == 0) {
      if (host_line_len_without_port >= 8 + 5 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 5], "rapid", 5) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == '.')) {
	goto end_ddl_found;
      }
      if (host_line_len_without_port >= 8 + 5 + 1
	  && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 5], "ultra", 5) == 0
	  && (packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == ' '
	      || packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == '.')) {
	goto end_ddl_found;
      }
      goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 3 + 15 + 1
	&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 15], "uploadyourfiles", 15) == 0
	&& (packet->host_line.ptr[host_line_len_without_port - 3 - 15 - 1] == ' '
	    || packet->host_line.ptr[host_line_len_without_port - 3 - 15 - 1] == '.')) {
      goto end_ddl_found;
    }
    goto end_ddl_nothing_found;
  }
  if (host_line_len_without_port >= 0 + 14 + 1
      && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 14], "speedshare.org", 14) == 0
      && (packet->host_line.ptr[host_line_len_without_port - 0 - 14 - 1] == ' '
	  || packet->host_line.ptr[host_line_len_without_port - 0 - 14 - 1] == '.')) {
    goto end_ddl_found;
  }
  // END OF AUTOMATED CODE GENERATION

  /* This is the hard way. We do this in order to find the download of services when other
     domains are involved. This is not significant if ddl is blocked. --> then the link can not be started because
     the ads are not viewed. But when ddl is only limited then the download is the important part.
  */

 end_ddl_nothing_found:
  NDPI_LOG_DBG2(ndpi_struct,
	   "Nothing Found\n");
  return 0;

 end_ddl_found:
  NDPI_LOG_INFO(ndpi_struct, "found DIRECT DOWNLOAD LINK\n");
  ndpi_int_direct_download_link_add_connection(ndpi_struct, flow);
  return 1;
}


void ndpi_search_direct_download_link_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  /* do not detect again if it is already ddl */
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK) {
    if (search_ddl_domains(ndpi_struct, flow) != 0) {
      return;
    }
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }

}

void init_directdownloadlink_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Direct_Download_Link", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK,
				      ndpi_search_direct_download_link_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);  

  *id += 1;
}

