/*
 * secondlife.c
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


#include "ndpi_utils.h"
#ifdef NDPI_PROTOCOL_SECONDLIFE

static void ndpi_int_secondlife_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					       struct ndpi_flow_struct *flow,
					       ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SECONDLIFE, protocol_type);
}

void ndpi_search_secondlife(struct ndpi_detection_module_struct
			    *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  //  if ((ntohs(packet->udp->dest) == 12035 || ntohs(packet->udp->dest) == 12036 || (ntohs(packet->udp->dest) >= 13000 && ntohs(packet->udp->dest) <= 13050))    //port
  //      && packet->payload_packet_len > 6   // min length with no extra header, high frequency and 1 byte message body
  //      && get_u_int8_t(packet->payload, 0) == 0x40   // reliable packet
  //      && ntohl(get_u_int32_t(packet->payload, 1)) == 0x00000001 // sequence number equals 1
  //      //ntohl (get_u_int32_t (packet->payload, 5)) == 0x00FFFF00      // no extra header, low frequency message - can't use, message may have higher frequency
  //      ) {
  //      NDPI_LOG(NDPI_PROTOCOL_SECONDLIFE, ndpi_struct, NDPI_LOG_DEBUG, "Second Life detected.\n");
  //      ndpi_int_secondlife_add_connection(ndpi_struct, flow);
  //      return;
  //  }

  if (packet->tcp != NULL) {
    if (packet->payload_packet_len > NDPI_STATICSTRING_LEN("GET /")
	&& memcmp(packet->payload, "GET /", NDPI_STATICSTRING_LEN("GET /")) == 0) {
      NDPI_LOG(NDPI_PROTOCOL_SECONDLIFE, ndpi_struct, NDPI_LOG_DEBUG, "Second Life HTTP 'GET /'' found.\n");
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      if (packet->user_agent_line.ptr != NULL
	  && packet->user_agent_line.len >
	  NDPI_STATICSTRING_LEN
	  ("Mozilla/5.0 (Windows; U; Windows NT 6.1; de-DE) AppleWebKit/532.4 (KHTML, like Gecko) SecondLife/")
	  && memcmp(&packet->user_agent_line.ptr[NDPI_STATICSTRING_LEN
						 ("Mozilla/5.0 (Windows; U; Windows NT 6.1; de-DE) AppleWebKit/532.4 (KHTML, like Gecko) ")],
		    "SecondLife/", NDPI_STATICSTRING_LEN("SecondLife/")) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_SECONDLIFE, ndpi_struct, NDPI_LOG_DEBUG,
		 "Second Life TCP HTTP User Agent detected.\n");
	ndpi_int_secondlife_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
	return;
      }
      if (packet->host_line.ptr != NULL && packet->host_line.len > NDPI_STATICSTRING_LEN(".agni.lindenlab.com:")) {
	u_int8_t x;
	for (x = 2; x < 6; x++) {
	  if (packet->host_line.ptr[packet->host_line.len - (1 + x)] == ':') {
	    if ((1 + x + NDPI_STATICSTRING_LEN(".agni.lindenlab.com")) < packet->host_line.len
		&& memcmp(&packet->host_line.ptr[packet->host_line.len -
						 (1 + x + NDPI_STATICSTRING_LEN(".agni.lindenlab.com"))],
			  ".agni.lindenlab.com", NDPI_STATICSTRING_LEN(".agni.lindenlab.com")) == 0) {
	      NDPI_LOG(NDPI_PROTOCOL_SECONDLIFE, ndpi_struct, NDPI_LOG_DEBUG,
		       "Second Life TCP HTTP Host detected.\n");
	      ndpi_int_secondlife_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
	      return;
	    }
	    break;
	  }
	}
      }
    }
  }
  if (packet->udp != NULL) {
    if (packet->payload_packet_len == 46
	&& memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\xff\xff\x00\x03", 10) == 0) {
      NDPI_LOG(NDPI_PROTOCOL_SECONDLIFE, ndpi_struct, NDPI_LOG_DEBUG, "Second Life 0xffff0003 detected.\n");
      ndpi_int_secondlife_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }
    if (packet->payload_packet_len == 54
	&& memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\xff\xff\x00\x52", 10) == 0) {
      NDPI_LOG(NDPI_PROTOCOL_SECONDLIFE, ndpi_struct, NDPI_LOG_DEBUG, "Second Life 0xffff0052 detected.\n");
      ndpi_int_secondlife_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }
    if (packet->payload_packet_len == 58
	&& memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\xff\xff\x00\xa9", 10) == 0) {
      NDPI_LOG(NDPI_PROTOCOL_SECONDLIFE, ndpi_struct, NDPI_LOG_DEBUG, "Second Life 0xffff00a9 detected.\n");
      ndpi_int_secondlife_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }
    if (packet->payload_packet_len > 54 && memcmp(packet->payload, "\x40\x00\x00\x00\x01\x00\x08", 7) == 0 &&
	get_u_int32_t(packet->payload, packet->payload_packet_len - 4) == 0) {
      NDPI_LOG(NDPI_PROTOCOL_SECONDLIFE, ndpi_struct, NDPI_LOG_DEBUG, "Second Life 0x08 detected.\n");
      ndpi_int_secondlife_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }
  }


  NDPI_LOG(NDPI_PROTOCOL_SECONDLIFE, ndpi_struct, NDPI_LOG_DEBUG, "Second Life excluded.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SECONDLIFE);
}

#endif
