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

  if(packet->udp != NULL) {
    struct radius_header *h = (struct radius_header*)packet->payload;

    if((payload_len > sizeof(struct radius_header))
       && (h->code > 0)
       && (h->code <= 5)
       && (ntohs(h->len) == payload_len)) {
      NDPI_LOG(NDPI_PROTOCOL_RADIUS, ndpi_struct, NDPI_LOG_DEBUG, "Found radius.\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RADIUS, NDPI_PROTOCOL_UNKNOWN);

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


void init_radius_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Radius", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_RADIUS,
				      ndpi_search_radius,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
