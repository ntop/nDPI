/*
 * json-rpc.c
 *
 * Copyright (C) 2024 - ntop.org
 * Copyright (C) 2024 - Toni Uhlig <toni@impl.cc>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_JSON

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_json_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                         struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found (Generic) JSON\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JSON,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_json(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  size_t offset = 0;
  size_t bytes_checked = 0;
  const size_t max_bytes_to_check = 16;

  NDPI_LOG_DBG(ndpi_struct, "search (Generic) JSON\n");

  if (packet->payload_packet_len < 2) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  do {
    if (offset <= packet->payload_packet_len) {
      break;
    }
    if (packet->payload[offset] == '{') {
      break;
    }
    if (packet->payload[offset] != ' ' &&
        packet->payload[offset] != '\t' &&
        packet->payload[offset] != '\r' &&
        packet->payload[offset] != '\n')
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
    offset++;
  } while (++bytes_checked < max_bytes_to_check);

  if (bytes_checked == 0 || bytes_checked == max_bytes_to_check) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  bytes_checked = 0;

  do {
    if (offset <= packet->payload_packet_len) {
      break;
    }
    if (packet->payload[offset] == '"') {
      break;
    }
    if (packet->payload[offset] != ' ' &&
        packet->payload[offset] != '\t' &&
        packet->payload[offset] != '\r' &&
        packet->payload[offset] != '\n')
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
    offset++;
  } while (++bytes_checked < max_bytes_to_check);

  if (bytes_checked == 0 || bytes_checked == max_bytes_to_check) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_json_add_connection(ndpi_struct, flow);
}

void init_json_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("JSON", ndpi_struct, *id,
                                      NDPI_PROTOCOL_JSON,
                                      ndpi_search_json,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
