/*
 * icecast.c
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

#ifdef NDPI_PROTOCOL_ICECAST

static void ndpi_int_icecast_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_ICECAST, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_icecast_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t i;

  NDPI_LOG(NDPI_PROTOCOL_ICECAST, ndpi_struct, NDPI_LOG_DEBUG, "search icecast.\n");

  if ((packet->payload_packet_len < 500 &&
       packet->payload_packet_len >= 7 && memcmp(packet->payload, "SOURCE ", 7) == 0)
      || flow->l4.tcp.icecast_stage) {
    ndpi_parse_packet_line_info_any(ndpi_struct, flow);
    NDPI_LOG(NDPI_PROTOCOL_ICECAST, ndpi_struct, NDPI_LOG_DEBUG, "Icecast lines=%d\n", packet->parsed_lines);
    for (i = 0; i < packet->parsed_lines; i++) {
      if (packet->line[i].ptr != NULL && packet->line[i].len > 4
	  && memcmp(packet->line[i].ptr, "ice-", 4) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_ICECAST, ndpi_struct, NDPI_LOG_DEBUG, "Icecast detected.\n");
	ndpi_int_icecast_add_connection(ndpi_struct, flow);
	return;
      }
    }

    if (packet->parsed_lines < 1 && !flow->l4.tcp.icecast_stage) {
      flow->l4.tcp.icecast_stage = 1;
      return;
    }
  }
#ifdef NDPI_PROTOCOL_HTTP
  if (NDPI_FLOW_PROTOCOL_EXCLUDED(ndpi_struct, flow, NDPI_PROTOCOL_HTTP)) {
    goto icecast_exclude;
  }
#endif

  if (packet->packet_direction == flow->setup_packet_direction && flow->packet_counter < 10) {
    return;
  }

  if (packet->packet_direction != flow->setup_packet_direction) {
    /* server answer, now test Server for Icecast */

    ndpi_parse_packet_line_info(ndpi_struct, flow);

    if (packet->server_line.ptr != NULL && packet->server_line.len > NDPI_STATICSTRING_LEN("Icecast") &&
	memcmp(packet->server_line.ptr, "Icecast", NDPI_STATICSTRING_LEN("Icecast")) == 0) {
      NDPI_LOG(NDPI_PROTOCOL_ICECAST, ndpi_struct, NDPI_LOG_DEBUG, "Icecast detected.\n");
      /* TODO maybe store the previous protocol type as subtype?
       *      e.g. ogg or mpeg
       */
      ndpi_int_icecast_add_connection(ndpi_struct, flow);
      return;
    }
  }

 icecast_exclude:
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_ICECAST);
  NDPI_LOG(NDPI_PROTOCOL_ICECAST, ndpi_struct, NDPI_LOG_DEBUG, "Icecast excluded.\n");
}
#endif
