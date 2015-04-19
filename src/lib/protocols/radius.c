/*
 * radius.c
 *
 * Copyright (C) 2012-15 - ntop.org
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

#ifdef NDPI_PROTOCOL_RADIUS

struct radius_header {
  u_int8_t code;
  u_int8_t packet_id;
  u_int16_t len;
};

static void ndpi_check_radius(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;  
  // const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;

#if 0
  printf("[len=%u][%02X %02X %02X %02X]\n", payload_len,
	 packet->payload[0] & 0xFF,
	 packet->payload[1] & 0xFF,
	 packet->payload[2] & 0xFF,
	 packet->payload[3] & 0xFF);
#endif

  if(packet->udp != NULL) {
    struct radius_header *h = (struct radius_header*)packet->payload;
    u_int len = ntohs(h->len);

    if((payload_len > sizeof(struct radius_header))
       && (h->code > 0)
       && (h->code <= 5)
       && (len == payload_len)) {
      NDPI_LOG(NDPI_PROTOCOL_RADIUS, ndpi_struct, NDPI_LOG_DEBUG, "Found radius.\n");
      ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RADIUS, NDPI_REAL_PROTOCOL);	
      
      return;
    }
    
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RADIUS);
    return;
  }
}

void ndpi_search_radius(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_RADIUS, ndpi_struct, NDPI_LOG_DEBUG, "radius detection...\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_RADIUS)
    ndpi_check_radius(ndpi_struct, flow);
}

#endif
