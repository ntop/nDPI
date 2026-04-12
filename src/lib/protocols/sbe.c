/*
 * sbe.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SBE

#include "ndpi_api.h"
#include "ndpi_define.h"
#include "ndpi_private.h"
#include "ndpi_typedefs.h"

#include <stdint.h>

PACK_ON
struct SOFH {
  // Simple Open Framing Header
  uint32_t message_length;
  uint16_t encoding_type;
} PACK_OFF;

PACK_ON
struct SBE {
  // Simple Binary Encoding
  uint16_t block_length;
  uint16_t template_id;
  uint16_t schema_id;
  uint16_t version;
} PACK_OFF;

/**
 * SBE Protocol:
 *   SBE Header
 *   Root block (fixed fields)
 *   Repeating groups
 *     group header
 *     elements
 *   Variable fields
 *     length + bytes
 */

static void ndpi_int_sbe_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                        struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found SBE (Simple Binary Encoding)\n");
  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
    ndpi_set_detected_protocol_keeping_master(ndpi_struct, flow, NDPI_PROTOCOL_SBE, NDPI_CONFIDENCE_DPI);
  } else {
    ndpi_set_detected_protocol(ndpi_struct, flow,
                               NDPI_PROTOCOL_SBE,
                               NDPI_PROTOCOL_UNKNOWN,
                               NDPI_CONFIDENCE_DPI);
  }
}

void ndpi_search_sbe(struct ndpi_detection_module_struct *ndpi_struct,
                     struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search SBE (Simple Binary Encoding)\n");

  if (packet->payload_packet_len < sizeof(struct SOFH) + sizeof(struct SBE)) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }
  struct SOFH const * const header = (struct SOFH *)&packet->payload[0];

  int is_little_endian;
  if (header->encoding_type == ntohs(0xEB50)) {
    is_little_endian = 1;
  } else if (header->encoding_type == ntohs(0x50EB)) {
    is_little_endian = 0;
  } else {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if (packet->udp != NULL && packet->payload_packet_len != ntohl(header->message_length)) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }
  if (packet->tcp != NULL && packet->payload_packet_len > ntohl(header->message_length)) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  struct SBE const * const sbe = (struct SBE *)(header + 1);
  const uint16_t block_length = (is_little_endian == 0 ? be16toh(sbe->block_length)
                                                       : le16toh(sbe->block_length));
  if (packet->payload_packet_len < block_length + sizeof(*header) + sizeof(*sbe)) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  ndpi_int_sbe_add_connection(ndpi_struct, flow);
}

void init_sbe_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("SimpleBinaryEncoding", ndpi_struct,
                          ndpi_search_sbe,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_SBE);
}
