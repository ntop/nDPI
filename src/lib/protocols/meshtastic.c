/*
 * meshtastic.c
 *
 * Meshtastic Client API (Serial/TCP/BLE)
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MESHTASTIC

#include "ndpi_api.h"
#include "ndpi_private.h"

#define MESHTASTIC_MAX_PROTOBUF_LEN 512

PACK_ON
struct meshtastic_header {
  uint16_t start_bytes_be;
  uint16_t length_be;
} PACK_OFF;

extern size_t protobuf_dissect(unsigned char const * const buffer, size_t const size,
                               size_t * const protobuf_elements,
                               size_t * const protobuf_len_elements);

static void ndpi_int_meshtastic_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                               struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Meshtastic\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_MESHTASTIC,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ***************************************************** */

static void ndpi_search_meshtastic(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  struct meshtastic_header const * const mhdr = (struct meshtastic_header *)&packet->payload[0];

  NDPI_LOG_DBG(ndpi_struct, "search Meshtastic\n");

  if (packet->payload_packet_len < sizeof(*mhdr))
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if (mhdr->start_bytes_be != be16toh(0x94C3))
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  const uint16_t protobuf_len = be16toh(mhdr->length_be);
  if (protobuf_len > MESHTASTIC_MAX_PROTOBUF_LEN
      || protobuf_len != packet->payload_packet_len - sizeof(*mhdr))
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  size_t protobuf_elements = 0;
  size_t protobuf_len_elements = 0;
  if (protobuf_len > 0
      && protobuf_dissect(&packet->payload[sizeof(*mhdr)], protobuf_len,
                          &protobuf_elements, &protobuf_len_elements) != protobuf_len)
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }
  if (protobuf_elements == 0 && protobuf_len_elements == 0)
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  ndpi_int_meshtastic_add_connection(ndpi_struct, flow);
}

/* ***************************************************** */

void init_meshtastic_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Meshtastic", ndpi_struct,
                          ndpi_search_meshtastic,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_MESHTASTIC);
}
