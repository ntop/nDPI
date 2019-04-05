/*
 * coap.c
 *
 * Copyright (C) 2016 Sorin Zamfir <sorin.zamfir@yahoo.com>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_COAP

#include "ndpi_api.h"


#define CON     0
#define NO_CON  1
#define ACK     2
#define RST     3

struct ndpi_coap_hdr
{
#if defined(__BIG_ENDIAN__)
  u_int8_t version:2, type:2, tkl:4;
#elif defined(__LITTLE_ENDIAN__)
  u_int8_t tkl:4, type:2, version:2;
#endif
  u_int8_t code;
  u_int16_t message_id; //if needed, remember to convert in host number
};


/**
   VALUE OF -CODE- FIELD

   [0]   = "Empty",
   [1]   = "GET",
   [2]   = "POST",
   [3]   = "PUT",
   [4]   = "DELETE",
   [65]  = "2.01 Created",
   [66]  = "2.02 Deleted",
   [67]  = "2.03 Valid",
   [68]  = "2.04 Changed",
   [69]  = "2.05 Content",
   [128] = "4.00 Bad Request",
   [129] = "4.01 Unauthorized",
   [130] = "4.02 Bad Option",
   [131] = "4.03 Forbidden",
   [132] = "4.04 Not Found",
   [133] = "4.05 Method Not Allowed",
   [134] = "4.06 Not Acceptable",
   [140] = "4.12 Precondition Failed",
   [141] = "4.13 Request Entity Too Large",
   [143] = "4.15 Unsupported Content-Format",
   [160] = "5.00 Internal Server Error",
   [161] = "5.01 Not Implemented",
   [162] = "5.02 Bad Gateway",
   [163] = "5.03 Service Unavailable",
   [164] = "5.04 Gateway Timeout",
   [165] = "5.05 Proxying Not Supported"
**/


/**
 * Entry point when protocol is identified.
 */
static void ndpi_int_coap_add_connection (struct ndpi_detection_module_struct *ndpi_struct,
					  struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct,flow,NDPI_PROTOCOL_COAP,NDPI_PROTOCOL_UNKNOWN);
}

/**
 * Check if the default port is acceptable 
 *
 * UDP Port 5683 (mandatory)
 * UDP Ports 61616-61631 compressed 6lowPAN
 */
static int isCoAPport(u_int16_t port) {
  if((port == 5683)
     || ((port >= 61616) && (port <= 61631)))
    return(1);
  else
    return(0);
}

/**
 * Dissector function that searches CoAP headers
 */
void ndpi_search_coap (struct ndpi_detection_module_struct *ndpi_struct,
		       struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ndpi_coap_hdr * h = (struct ndpi_coap_hdr*) packet->payload;

  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
    return;
  }

  // search for udp packet
  if(packet->udp != NULL) {
    u_int16_t s_port = ntohs(flow->packet.udp->source);
    u_int16_t d_port = ntohs(flow->packet.udp->dest);

    if((!isCoAPport(s_port) && !isCoAPport(d_port))
       || (packet->payload_packet_len < 4) ) {   // header too short
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    NDPI_LOG_DBG2(ndpi_struct, "calculating coap over udp\n");

    // check values in header
    if(h->version == 1) {
      if(h->type == CON || h->type == NO_CON || h->type == ACK || h->type == RST ) {
	if(h->tkl < 8) {
	  if((/* h->code >= 0 && */ h->code <= 5) || (h->code >= 65 && h->code <= 69) ||
	     (h->code >= 128  && h->code <= 134) || (h->code >= 140 && h->code <= 143) ||
	     (h->code >= 160 && h->code <= 165)) {

	    NDPI_LOG_INFO(ndpi_struct, "found Coap\n");
	    ndpi_int_coap_add_connection(ndpi_struct,flow);
	    return;
	  }
	}
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  return;
}

/**
 * Entry point for the ndpi library
 */
void init_coap_dissector (struct ndpi_detection_module_struct *ndpi_struct,
			  u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection ("COAP", ndpi_struct, detection_bitmask, *id,
				       NDPI_PROTOCOL_COAP,
				       ndpi_search_coap,
				       NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				       SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);
  *id +=1;
}

