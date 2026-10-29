/*
 * l2tp.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_L2TP

#include "ndpi_api.h"
#include "ndpi_private.h"

#define MIN_L2TP_SIZE (2u /* Flags and Version */ + 2u /* Length */ + 4u /* ID(s) */)
#define MIN_ATTR_SIZE (6u)
#define MAX_ATTR_DISSECT (32u)

static void ndpi_int_l2tp_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                         struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Layer 2 Tunneling Protocol (L2TP)\n");
  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_L2TP,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_int_l2tp_dissect_attrs(struct ndpi_flow_struct * const flow,
                                        u_int8_t const * const payload,
                                        u_int32_t const payload_len)
{
  uint8_t attrs_found = 0;
  for (u_int32_t i = 0; i < payload_len && attrs_found < MAX_ATTR_DISSECT;)
  {
    if (i + MIN_ATTR_SIZE >= payload_len) {
      break;
    }

    const u_int16_t attr_length = (ntohs(get_u_int16_t(payload, i)) & 0x3FF);
    if (attr_length < MIN_ATTR_SIZE || i + attr_length >= payload_len) {
      break;
    }

    const uint16_t attr = ntohs(get_u_int16_t(payload, i + 4)); // AVP Type
    if (attr_length > MIN_ATTR_SIZE && attr == 7 /* host */) {
      ndpi_hostname_sni_set(flow, &payload[i + MIN_ATTR_SIZE], attr_length - MIN_ATTR_SIZE,
                            NDPI_HOSTNAME_NORM_ALL);
    }

    i += attr_length;
    attrs_found++;
  }
}

static void ndpi_search_l2tp(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Layer 2 Tunneling Protocol (L2TP)\n");

  uint16_t required_size = MIN_L2TP_SIZE;
  if (packet->payload_packet_len < required_size) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  const uint8_t flags = packet->payload[0];
  if ((flags & 0x40) == 0) {
    // Length bit not set
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  const uint16_t length = ntohs(get_u_int16_t(packet->payload, 2));
  if (length != packet->payload_packet_len) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  const uint8_t version = packet->payload[1]; // high nibble: always 0, low nibble: 2 or 3 (L2TP version)
  if (version != 2 && version != 3) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if (version == 2 && (flags & 0xCB) == 0xC8) {
    // Type: Control Message
    // Length, Sequence, Offset and Priority bit unset
    uint8_t const offset = 2 /* flags/version */ + 2 /* length */ + 8 /* TID, SID, Ns, Nr */;
    uint8_t const * const remaining_payload = packet->payload + offset;
    u_int32_t const remaining_size = packet->payload_packet_len - offset;
    ndpi_int_l2tp_dissect_attrs(flow, remaining_payload, remaining_size);
  }

  ndpi_int_l2tp_add_connection(ndpi_struct, flow);
}

void init_l2tp_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("L2TP", ndpi_struct,
                          ndpi_search_l2tp,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                          DISSECTOR_LICENSE_LGPL,
                          1, NDPI_PROTOCOL_L2TP);
}
