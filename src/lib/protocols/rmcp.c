/*
 * rmcp.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RMCP

#include "ndpi_api.h"
#include "ndpi_private.h"

PACK_ON
struct rmcp_header {
  uint8_t version;
  uint8_t reserved;
  uint8_t sequence;
#if defined(__BIG_ENDIAN__)
  uint8_t type : 1; // Either Normal RMCP (0) or ACK (1)
  uint8_t class : 7;
#elif defined(__LITTLE_ENDIAN__)
  uint8_t class : 7;
  uint8_t type : 1; // Either Normal RMCP (0) or ACK (1)
#else
#error "Missing endian macro definitions."
#endif
} PACK_OFF;

static void ndpi_int_rmcp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                         struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RMCP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_rmcp(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search RMCP\n");

  if (packet->payload_packet_len < sizeof(struct rmcp_header)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  struct rmcp_header const * const rmcp_header = (struct rmcp_header *)packet->payload;

  if (rmcp_header->version != 0x06 || rmcp_header->reserved != 0x00) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (rmcp_header->type != 0 && rmcp_header->sequence == 0xFF) {
    // No ACK allowed if SEQUENCE number is 255.
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (rmcp_header->class != 0x06 /* Alert Standard Forum (ASF)*/
      && rmcp_header->class != 0x07 /* Intelligent Platform Management Interface (IPMI) */)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_rmcp_add_connection(ndpi_struct, flow);
}


void init_rmcp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("RMCP", ndpi_struct, *id,
                                      NDPI_PROTOCOL_RMCP,
                                      ndpi_search_rmcp,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

