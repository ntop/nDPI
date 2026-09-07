/*
 * nebula.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NEBULA

#include "ndpi_api.h"
#include "ndpi_private.h"

PACK_ON
struct nebula_header {
  uint8_t version : 4;
  uint8_t type : 4;
  uint8_t subtype;
  uint16_t reserved;
  uint32_t remote_index;
  uint64_t message_counter;
} PACK_OFF;

static void ndpi_int_nebula_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                           struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Nebula\n");
  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_NEBULA,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_nebula(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  struct nebula_header const * const nhdr = (struct nebula_header *)&packet->payload[0];

  NDPI_LOG_DBG(ndpi_struct, "search Nebula\n");

  if (packet->payload_packet_len < sizeof(*nhdr)) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if (nhdr->version != 0x1
      || nhdr->type > 0x6 || nhdr->subtype > 0x1
      || nhdr->reserved != 0x0000)
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  // Some type do not allow any subtypes
  switch (nhdr->type) {
    case 2: // RecvError
    case 3: // LightHouse
    case 5: // CloseTunnel
    case 6: // Control
      if (nhdr->subtype != 0x00) {
        NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
        return;
      }
  }

  const uint64_t message_counter = be64toh(nhdr->message_counter);
  // First Handshake message must have set all remote index bits to zero
  if (ntohl(nhdr->remote_index) != 0 && message_counter == 1) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if (flow->core.packet_counter != message_counter) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  ndpi_int_nebula_add_connection(ndpi_struct, flow);
}

void init_nebula_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Nebula", ndpi_struct,
                          ndpi_search_nebula,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                          DISSECTOR_LICENSE_LGPL,
                          1, NDPI_PROTOCOL_NEBULA);
}

