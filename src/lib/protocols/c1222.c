/*
 * c1222.c
 *
 * ANSI C12.22 (IEEE Std 1703)
 * 
 * Copyright (C) 2024 - ntop.org
 * Copyright (C) 2024 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_C1222

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_c1222_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                          struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found ANSI C12.22\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_C1222, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_c1222(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search ANSI C12.22\n");

  if ((packet->payload_packet_len < 50) || (packet->payload[0] != 0x60) ||
      ((u_int8_t)(packet->payload_packet_len-2) != packet->payload[1]))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (packet->payload[2] == 0xA2 && packet->payload[4] == 0x06) {
    ndpi_int_c1222_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_c1222_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("ANSI_C1222", ndpi_struct, *id,
                                      NDPI_PROTOCOL_C1222,
                                      ndpi_search_c1222,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
