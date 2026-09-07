/*
 * yggdrasil.c
 *
 * Copyright (C) 2026 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_YGGDRASIL

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_yggdrasil_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                              struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Yggdrasil\n");
  if (flow->core.detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
    ndpi_set_detected_protocol_keeping_master(ndpi_struct, flow, NDPI_PROTOCOL_YGGDRASIL,
                                              NDPI_CONFIDENCE_DPI);
  } else {
    ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                               NDPI_PROTOCOL_YGGDRASIL,
                               NDPI_PROTOCOL_UNKNOWN,
                               NDPI_CONFIDENCE_DPI);
  }
}

static int ndpi_search_yggdrasil_http(struct ndpi_detection_module_struct *ndpi_struct,
                                      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Yggdrasil\n");

  if (flow->core.detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP &&
      flow->core.detected_protocol_stack[1] != NDPI_PROTOCOL_HTTP)
  {
    return -1;
  }

  if (packet->parsed_lines == 0)
  {
    ndpi_parse_packet_line_info(ndpi_struct, flow);
  }

  if (packet->parsed_lines > 0)
  {
    size_t i;

    for (i = 0; i < packet->parsed_lines && packet->line[i].len > 0; ++i)
    {
      if (LINE_STARTS(packet->line[i], "Sec-Websocket-Protocol") != 0 &&
          LINE_ENDS(packet->line[i], "ygg-ws") != 0)
      {
        return 0;
      }
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  return -1;
}

static void ndpi_search_yggdrasil(struct ndpi_detection_module_struct *ndpi_struct,
                                  struct ndpi_flow_struct *flow)
{
  if (ndpi_search_yggdrasil_http(ndpi_struct, flow) == 0) {
    ndpi_int_yggdrasil_add_connection(ndpi_struct, flow);
    return;
  } else {
    struct ndpi_packet_struct *packet = &ndpi_struct->packet;

    if (packet->payload_packet_len < 5) {
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
      return;
    }

    if (get_u_int32_t(packet->payload, 0) == htonl(0x6D657461) // "meta"
        && get_u_int8_t(packet->payload, 4) == 0x00)
    {
      ndpi_int_yggdrasil_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_yggdrasil_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Yggdrasil", ndpi_struct,
                          ndpi_search_yggdrasil,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          DISSECTOR_LICENSE_LGPL,
                          1, NDPI_PROTOCOL_YGGDRASIL);
}
