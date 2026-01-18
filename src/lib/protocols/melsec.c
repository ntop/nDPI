/*
 * melsec.c
 *
 * MELSEC Communication Protocol
 * 
 * Copyright (C) 2025 - ntop.org
 * Copyright (C) 2025 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MELSEC

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_melsec(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search MELSEC\n");

  if (packet->payload_packet_len > 40 &&
      (packet->payload[0] == 0x57 || packet->payload[0] == 0xD7))
  {
    u_int16_t melsec_payload_len = packet->payload_packet_len - 21;
    if (le16toh(get_u_int16_t(packet->payload, 19)) == melsec_payload_len &&
        ntohl(get_u_int32_t(packet->payload, 3)) == 0x00001111)
    {
      NDPI_LOG_INFO(ndpi_struct, "found MELSEC\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MELSEC, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    }
  }

  if (flow->packet_counter > 2) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  }
}

void init_melsec_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("MELSEC", ndpi_struct,
                     ndpi_search_melsec,
                     NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                      1, NDPI_PROTOCOL_MELSEC);
}
