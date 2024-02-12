/*
 * portable_executable.c
 *
 * Copyright (C) 2024 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_PORTABLE_EXECUTABLE

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_portable_executable_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                                        struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Portable Executable (PE) file\n");
  if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
  {
    ndpi_set_detected_protocol(ndpi_struct, flow,
                               NDPI_PROTOCOL_PORTABLE_EXECUTABLE,
                               NDPI_PROTOCOL_UNKNOWN,
                               NDPI_CONFIDENCE_DPI);
  } else if (flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
    ndpi_set_detected_protocol(ndpi_struct, flow,
                               flow->detected_protocol_stack[0],
                               NDPI_PROTOCOL_PORTABLE_EXECUTABLE,
                               NDPI_CONFIDENCE_DPI);
  }
  ndpi_set_risk(ndpi_struct, flow, NDPI_BINARY_APPLICATION_TRANSFER, "Portable Executable (PE32/PE32+) found");
}

static void ndpi_search_portable_executable(struct ndpi_detection_module_struct *ndpi_struct,
                                            struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  static const uint16_t dos_signature = 0x4d5a; /* MZ */
  static const uint32_t pe_signature = 0x50450000; /* PE */

  NDPI_LOG_DBG(ndpi_struct, "search Portable Executable (PE) file\n");

  if (flow->packet_counter > 5)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (packet->payload_packet_len < 0x3C /* offset to PE header */ + 4)
  {
    return;
  }

  if (ntohs(get_u_int16_t(packet->payload, 0)) != dos_signature)
  {
    return;
  }

  uint32_t const pe_offset = le32toh(get_u_int32_t(packet->payload, 0x3C));
  if (packet->payload_packet_len <= pe_offset + 4 ||
      be32toh(get_u_int32_t(packet->payload, pe_offset)) != pe_signature)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_portable_executable_add_connection(ndpi_struct, flow);
}

void init_portable_executable_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                        u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Portable_Executable", ndpi_struct, *id,
                                      NDPI_PROTOCOL_PORTABLE_EXECUTABLE,
                                      ndpi_search_portable_executable,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

