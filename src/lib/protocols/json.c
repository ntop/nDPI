/*
 * json.c
 *
 * Copyright (C) 2011-26 - ntop.org
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

#define JSON_MAX_BYTES_TO_CHECK 16

static void ndpi_int_json_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                         struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found JSON\n");
  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
    ndpi_set_detected_protocol_keeping_master(ndpi_struct, flow, NDPI_PROTOCOL_JSON, NDPI_CONFIDENCE_DPI);
  } else {
    ndpi_set_detected_protocol(ndpi_struct, flow,
                               NDPI_PROTOCOL_JSON,
                               NDPI_PROTOCOL_UNKNOWN,
                               NDPI_CONFIDENCE_DPI);
  }
}

void ndpi_search_json(struct ndpi_detection_module_struct *ndpi_struct,
                      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  size_t offset = 0, i;
  size_t bytes_checked = 0;

  NDPI_LOG_DBG(ndpi_struct, "search JSON\n");

  if (packet->payload_packet_len < 2) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  do {
    if (offset >= packet->payload_packet_len) {
      break;
    }
    if (packet->payload[offset] == '{' ||
        packet->payload[offset] == '[')
    {
      break;
    }
    if (packet->payload[offset] != ' ' &&
        packet->payload[offset] != '\t' &&
        packet->payload[offset] != '\r' &&
        packet->payload[offset] != '\n' &&
        ndpi_isalnum(packet->payload[offset]) == 0 &&
        offset >= 8)
    {
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
      return;
    }
  } while (++offset < JSON_MAX_BYTES_TO_CHECK);

  for (i = offset; i < ndpi_min(JSON_MAX_BYTES_TO_CHECK, packet->payload_packet_len); ++i) {
    if (ndpi_isprint(packet->payload[i]) == 0 &&
        packet->payload[i] != '\t' &&
        packet->payload[i] != '\r' &&
        packet->payload[i] != '\n')
    {
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
      return;
    }
  }

  if (offset == JSON_MAX_BYTES_TO_CHECK || offset >= packet->payload_packet_len) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  offset = packet->payload_packet_len;

  do {
    if (packet->payload[offset - 1] == '}' ||
        packet->payload[offset - 1] == ']')
    {
      break;
    }
    if (packet->payload[offset - 1] != ' ' &&
        packet->payload[offset - 1] != '\t' &&
        packet->payload[offset - 1] != '\r' &&
        packet->payload[offset - 1] != '\n' &&
        ndpi_isalnum(packet->payload[offset - 1]) == 0)
    {
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
      return;
    }
  } while (--offset > 0 && ++bytes_checked < JSON_MAX_BYTES_TO_CHECK);

  ndpi_int_json_add_connection(ndpi_struct, flow);
}

void init_json_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("JSON", ndpi_struct,
                     ndpi_search_json,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_JSON);
}
