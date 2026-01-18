/*
 * rtsp.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RTSP

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_rtsp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found RTSP\n");
  ndpi_set_detected_protocol_keeping_master(ndpi_struct, flow, NDPI_PROTOCOL_RTSP,
					    NDPI_CONFIDENCE_DPI);
}

/* this function searches for a rtsp-"handshake" over tcp or udp. */
static void ndpi_search_rtsp_tcp_udp(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search RTSP\n");

  if (packet->parsed_lines == 0)
  {
    ndpi_parse_packet_line_info(ndpi_struct, flow);
  }

  if (packet->parsed_lines > 0 &&
      (LINE_ENDS(packet->line[0], "RTSP/1.0") != 0 ||
       LINE_STARTS(packet->line[0], "RTSP/1.0") != 0 || /* Response */
       LINE_ENDS(packet->accept_line, "application/x-rtsp-tunnelled") != 0 ||
       LINE_ENDS(packet->content_line, "application/x-rtsp-tunnelled") != 0
       /* Should we also check for "rtsp://" in the packet? */))
  {
    ndpi_int_rtsp_add_connection(ndpi_struct, flow);

    /* Extract some metadata HTTP-like */
    if(packet->user_agent_line.ptr != NULL)
      ndpi_user_agent_set(flow, packet->user_agent_line.ptr, packet->user_agent_line.len);

    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}


void init_rtsp_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("RTSP", ndpi_struct,
                     ndpi_search_rtsp_tcp_udp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_RTSP);
}
