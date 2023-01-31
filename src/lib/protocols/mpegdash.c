/*
 * mpegdash.c
 *
 * Copyright (C) 2022-23 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MPEGDASH

#include "ndpi_api.h"


static void ndpi_int_mpegdash_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                             struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found MpegDash\n");
  ndpi_set_detected_protocol_keeping_master(ndpi_struct, flow, NDPI_PROTOCOL_MPEGDASH,
					    NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_mpegdash_http(struct ndpi_detection_module_struct *ndpi_struct,
                                      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search MpegDash\n");

  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP &&
      flow->detected_protocol_stack[1] != NDPI_PROTOCOL_HTTP)
  {
    if (flow->packet_counter > 2)
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
    return;
  }

  if (packet->parsed_lines == 0)
  {
    ndpi_parse_packet_line_info(ndpi_struct, flow);
  }

  if (packet->parsed_lines > 0)
  {
    size_t i;

    if (LINE_ENDS(packet->line[0], "RTSP/1.0") != 0 ||
        LINE_ENDS(packet->line[0], ".mp4 HTTP/1.1") != 0 ||
        LINE_ENDS(packet->line[0], ".m4s HTTP/1.1") != 0)
    {
      ndpi_int_mpegdash_add_connection(ndpi_struct, flow);
      return;
    }

    for (i = 0; i < packet->parsed_lines && packet->line[i].len > 0; ++i)
    {
      if ((LINE_STARTS(packet->line[i], "Content-Type:") != 0 &&
           LINE_ENDS(packet->line[i], "video/mp4") != 0) ||
          LINE_STARTS(packet->line[i], "DASH") != 0)
      {
        ndpi_int_mpegdash_add_connection(ndpi_struct, flow);
        return;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  return;
}

void init_mpegdash_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                             u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("MpegDash", ndpi_struct, *id,
				      NDPI_PROTOCOL_MPEGDASH,
				      ndpi_search_mpegdash_http,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
