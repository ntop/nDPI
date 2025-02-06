/*
 * can.c
 *
 * Copyright (C) 2023 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CAN

#include "ndpi_api.h"
#include "ndpi_private.h"

PACK_ON
struct can_hdr {
  uint64_t signature;
  uint8_t version;
  uint8_t frames;
} PACK_OFF;

static void ndpi_int_can_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                        struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Controller Area Network\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_CAN, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_can(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Controller Area Network\n");

  u_int64_t const signature = 0x49534f3131383938; // "ISO11898"
  if (packet->payload_packet_len < sizeof(struct can_hdr)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  struct can_hdr const * const can_header = (struct can_hdr *)packet->payload;
  if (ndpi_ntohll(can_header->signature) != signature) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_can_add_connection(ndpi_struct, flow);

  if (can_header->version != 0x01) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid CAN Header");
  }
}

void init_can_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                        u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Controller_Area_Network", ndpi_struct, *id,
                                      NDPI_PROTOCOL_CAN,
                                      ndpi_search_can,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
