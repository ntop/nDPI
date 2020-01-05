/*
 * icecast.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ICECAST

#include "ndpi_api.h"

static void ndpi_int_icecast_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ICECAST, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_icecast_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t i;

  NDPI_LOG_DBG(ndpi_struct, "search icecast\n");

  if((packet->payload_packet_len < 500 &&
       packet->payload_packet_len >= 7 && memcmp(packet->payload, "SOURCE ", 7) == 0)
      || flow->l4.tcp.icecast_stage) {
    ndpi_parse_packet_line_info_any(ndpi_struct, flow);
    NDPI_LOG_DBG2(ndpi_struct, "Icecast lines=%d\n", packet->parsed_lines);
    for (i = 0; i < packet->parsed_lines; i++) {
      if(packet->line[i].ptr != NULL && packet->line[i].len > 4
	  && memcmp(packet->line[i].ptr, "ice-", 4) == 0) {
	NDPI_LOG_INFO(ndpi_struct, "found Icecast\n");
	ndpi_int_icecast_add_connection(ndpi_struct, flow);
	return;
      }
    }

    if(packet->parsed_lines < 1 && !flow->l4.tcp.icecast_stage) {
      flow->l4.tcp.icecast_stage = 1;
      return;
    }
  }

  if(NDPI_FLOW_PROTOCOL_EXCLUDED(ndpi_struct, flow, NDPI_PROTOCOL_HTTP)) {
    goto icecast_exclude;
  }

  if(flow == NULL) return;
    
  if((packet->packet_direction == flow->setup_packet_direction)
      && (flow->packet_counter < 10)) {
    return;
  }

  if(packet->packet_direction != flow->setup_packet_direction) {
    /* server answer, now test Server for Icecast */

    ndpi_parse_packet_line_info(ndpi_struct, flow);

    if((packet->server_line.ptr != NULL)
       && (packet->server_line.len > NDPI_STATICSTRING_LEN("Icecast"))
       &&  memcmp(packet->server_line.ptr, "Icecast",
		  NDPI_STATICSTRING_LEN("Icecast")) == 0) {
      /* TODO maybe store the previous protocol type as subtype?
       *      e.g. ogg or mpeg
       */
      NDPI_LOG_INFO(ndpi_struct, "found Icecast\n");
      ndpi_int_icecast_add_connection(ndpi_struct, flow);
      return;
    }
  }

 icecast_exclude:
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_icecast_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("IceCast", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_ICECAST,
				      ndpi_search_icecast_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
