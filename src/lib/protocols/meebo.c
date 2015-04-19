/*
 * meebo.c
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


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_MEEBO

static void ndpi_int_meebo_add_connection(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MEEBO, NDPI_CORRELATED_PROTOCOL);
}




void ndpi_search_meebo(struct ndpi_detection_module_struct
		       *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	

  // struct ndpi_id_struct *src=ndpi_struct->src;
  // struct ndpi_id_struct *dst=ndpi_struct->dst;


  NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "search meebo.\n");

  /* catch audio/video flows which are flash (rtmp) */
  if (
#ifdef NDPI_CONTENT_FLASH
      packet->detected_protocol_stack[0] == NDPI_CONTENT_FLASH
#else
      (packet->tcp->source == htons(1935) || packet->tcp->dest == htons(1935))
#endif
      ) {

    /* TODO: once we have an amf decoder we can more directly access the rtmp fields
     *       if so, we may also exclude earlier */
    if (packet->payload_packet_len > 900) {
      if (memcmp(packet->payload + 116, "tokbox/", NDPI_STATICSTRING_LEN("tokbox/")) == 0 ||
	  memcmp(packet->payload + 316, "tokbox/", NDPI_STATICSTRING_LEN("tokbox/")) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "found meebo/tokbox flash flow.\n");
	ndpi_int_meebo_add_connection(ndpi_struct, flow);
	return;
      }
    }

    if (flow->packet_counter < 16 && flow->packet_direction_counter[flow->setup_packet_direction] < 6) {
      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "need next packet.\n");
      return;
    }

    NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "exclude meebo.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MEEBO);
    return;
  }

  if ((
#ifdef	NDPI_PROTOCOL_HTTP
       packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
#endif
       ((packet->payload_packet_len > 3 && memcmp(packet->payload, "GET ", 4) == 0)
	|| (packet->payload_packet_len > 4 && memcmp(packet->payload, "POST ", 5) == 0))
       ) && flow->packet_counter == 1) {
    u_int8_t host_or_referer_match = 0;

    ndpi_parse_packet_line_info(ndpi_struct, flow);
    if (packet->host_line.ptr != NULL
	&& packet->host_line.len >= 9
	&& memcmp(&packet->host_line.ptr[packet->host_line.len - 9], "meebo.com", 9) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found Meebo host\n");
      host_or_referer_match = 1;
    } else if (packet->host_line.ptr != NULL
	       && packet->host_line.len >= 10
	       && memcmp(&packet->host_line.ptr[packet->host_line.len - 10], "tokbox.com", 10) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found tokbox host\n");
      /* set it to 2 to avoid having plain tokbox traffic detected as meebo */
      host_or_referer_match = 2;
    } else if (packet->host_line.ptr != NULL && packet->host_line.len >= NDPI_STATICSTRING_LEN("74.114.28.110")
	       && memcmp(&packet->host_line.ptr[packet->host_line.len - NDPI_STATICSTRING_LEN("74.114.28.110")],
			 "74.114.28.110", NDPI_STATICSTRING_LEN("74.114.28.110")) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found meebo IP\n");
      host_or_referer_match = 1;
    } else if (packet->referer_line.ptr != NULL &&
	       packet->referer_line.len >= NDPI_STATICSTRING_LEN("http://www.meebo.com/") &&
	       memcmp(packet->referer_line.ptr, "http://www.meebo.com/",
		      NDPI_STATICSTRING_LEN("http://www.meebo.com/")) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found meebo referer\n");
      host_or_referer_match = 1;
    } else if (packet->referer_line.ptr != NULL &&
	       packet->referer_line.len >= NDPI_STATICSTRING_LEN("http://mee.tokbox.com/") &&
	       memcmp(packet->referer_line.ptr, "http://mee.tokbox.com/",
		      NDPI_STATICSTRING_LEN("http://mee.tokbox.com/")) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found tokbox referer\n");
      host_or_referer_match = 1;
    } else if (packet->referer_line.ptr != NULL &&
	       packet->referer_line.len >= NDPI_STATICSTRING_LEN("http://74.114.28.110/") &&
	       memcmp(packet->referer_line.ptr, "http://74.114.28.110/",
		      NDPI_STATICSTRING_LEN("http://74.114.28.110/")) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found meebo IP referer\n");
      host_or_referer_match = 1;
    }

    if (host_or_referer_match) {
      if (host_or_referer_match == 1) {
	NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG,
		 "Found Meebo traffic based on host/referer\n");
	ndpi_int_meebo_add_connection(ndpi_struct, flow);
	return;
      }
    }
  }

  if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_MEEBO) {
    NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG,
	     "in case that ssl meebo has been detected return.\n");
    return;
  }

  if (flow->packet_counter < 5 && packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN
      && NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SSL) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "ssl not yet excluded. need next packet.\n");
    return;
  }
#ifdef NDPI_CONTENT_FLASH
  if (flow->packet_counter < 5 && packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN &&
      !NDPI_FLOW_PROTOCOL_EXCLUDED(ndpi_struct, flow, NDPI_CONTENT_FLASH)) {
    NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "flash not yet excluded. need next packet.\n");
    return;
  }
#endif

  NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "exclude meebo.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MEEBO);
}
#endif
