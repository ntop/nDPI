/*
 * pfcp.c
 *
 * Packet Forwarding Control Protocol
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_PFCP

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_pfcp(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search PFCP\n");

  if (packet->payload_packet_len > 12 &&
      (ntohs(packet->udp->dest) == 8805 || ntohs(packet->udp->source) == 8805))
  {
    u_int8_t version = packet->payload[0] & 0x0F;
    /* Values from 18 to 49, 58 to 99 and 100 to 255 are reserved for future use 
     * and aren't used now. */
    u_int8_t message_type = packet->payload[1];
    if (version == 1 && (message_type <= 17 || (message_type - 50) <= 7) &&
        ntohs(get_u_int16_t(packet->payload, 2)) == (u_int16_t)(packet->payload_packet_len-4))
    {
      NDPI_LOG_INFO(ndpi_struct, "found PFCP\n");
      ndpi_set_detected_protocol(ndpi_struct, flow,
                                 NDPI_PROTOCOL_PFCP, NDPI_PROTOCOL_UNKNOWN,
                                 NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}
void init_pfcp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                             u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("PFCP", ndpi_struct, *id,
                                      NDPI_PROTOCOL_PFCP,
                                      ndpi_search_pfcp,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
