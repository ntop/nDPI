/*
 * tristation.c
 *
 * Copyright (C) 2025 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TRISTATION

#include "ndpi_api.h"
#include "ndpi_private.h"

PACK_ON
struct ts_header {
  uint8_t opcode;
  uint8_t channel;
  uint16_t length;
  uint8_t direction;
  uint8_t connection_id;
} PACK_OFF;

static void ndpi_int_tristation_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                               struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found TriStation Safety Instrumented Systems\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_TRISTATION,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_tristation(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search TriStation Safety Instrumented Systems\n");

  if (packet->payload_packet_len < sizeof(struct ts_header)) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  struct ts_header const * const hdr = (struct ts_header const *)&packet->payload[0];
  if (hdr->direction > 1) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  uint16_t len = le16toh(hdr->length);
  if (packet->payload_packet_len != len + 6) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  ndpi_int_tristation_add_connection(ndpi_struct, flow);
}

void init_tristation_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("TriStation", ndpi_struct,
                     ndpi_search_tristation,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                     1, NDPI_PROTOCOL_TRISTATION);
}
