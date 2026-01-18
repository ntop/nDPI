/*
 * gnutella.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_GNUTELLA

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_gnutella_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					     struct ndpi_flow_struct *flow,
					     ndpi_confidence_t confidence)
{
  NDPI_LOG_INFO(ndpi_struct, "found GNUTELLA\n");
  ndpi_set_detected_protocol_keeping_master(ndpi_struct, flow, NDPI_PROTOCOL_GNUTELLA,
					    confidence);
}

static void ndpi_search_gnutella(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search GNUTELLA\n");

  if (packet->tcp != NULL) {
    if (packet->payload_packet_len > 17 && memcmp(packet->payload, "GNUTELLA CONNECT/", 17) == 0) {
      ndpi_int_gnutella_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
      /* Extract some metadata HTTP-like */
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      if(packet->user_agent_line.ptr != NULL)
        ndpi_user_agent_set(flow, packet->user_agent_line.ptr, packet->user_agent_line.len);
      return;
    }
  } else if (packet->udp != NULL) {
    /* Check for Mojito-DHT encapsulated gnutella (gtk-gnutella). */
    if (packet->payload_packet_len > 23) {
      u_int32_t gnutella_payload_len = le32toh(get_u_int32_t(packet->payload, 19));

      if (gnutella_payload_len == (u_int32_t)packet->payload_packet_len - 23 &&
          ((packet->payload_packet_len > 27 &&
           ntohl(get_u_int32_t(packet->payload, 24)) == 0x47544b47 /* GTKG */) ||
           ntohl(get_u_int32_t(packet->payload, packet->payload_packet_len - 4)) == 0x82514b40)) {
        NDPI_LOG_DBG2(ndpi_struct, "detected mojito-dht/gnutella udp\n");
        ndpi_int_gnutella_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
        return;
      }
    }

    if (packet->payload_packet_len >= 4 && memcmp(packet->payload, "GND\x10", 4) == 0) {
      NDPI_LOG_DBG2(ndpi_struct, "detected gnutella udp, GND (2)\n");
      ndpi_int_gnutella_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}


void init_gnutella_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Gnutella", ndpi_struct,
                     ndpi_search_gnutella,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_GNUTELLA);
}

