/*
 * gearman.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_GEARMAN

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_gearman(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Gearman\n");

  if (packet->payload_packet_len > 12 && packet->payload[0] == 0) {
    if ((memcmp(&packet->payload[1], "REQ", 3) == 0) ||
        (memcmp(&packet->payload[1], "RES", 3) == 0))
    {
      NDPI_LOG_INFO(ndpi_struct, "found Gearman\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_GEARMAN,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_gearman_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Gearman", ndpi_struct,
                     ndpi_search_gearman,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_GEARMAN);
}
