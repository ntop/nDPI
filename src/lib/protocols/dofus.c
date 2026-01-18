/*
 * dofus.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DOFUS

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_dofus_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DOFUS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  NDPI_LOG_INFO(ndpi_struct, "found dofus\n");
}

static void ndpi_search_dofus(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search dofus\n");

  /* Dofus 3 */
  if(ntohs(flow->c_port) == 5555 || ntohs(flow->s_port) == 5555) {
    if(packet->payload_packet_len > 3 &&
       packet->payload[0] + 1 == packet->payload_packet_len &&
       packet->payload[1] == 0x0a &&
       packet->payload[2] + 2 ==  packet->payload[0]) {
      ndpi_dofus_add_connection(ndpi_struct, flow);
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_dofus_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Dofus", ndpi_struct,
                     ndpi_search_dofus,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_DOFUS);
}

