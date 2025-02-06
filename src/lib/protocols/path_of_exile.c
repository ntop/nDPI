/*
 * path_of_exile.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_PATHOFEXILE

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_pathofexile(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Path of Exile\n");

  /* Path of Exile 2 */
  if (packet->payload_packet_len == 19 && packet->payload[0] == 0) {
    if (ntohs(get_u_int16_t(packet->payload, 1)) == 0x300 &&
        ntohs(get_u_int16_t(packet->payload, 7)) == 0x200 &&
        ntohl(get_u_int32_t(packet->payload, 14)) == 0x40)
    {
      NDPI_LOG_INFO(ndpi_struct, "found Path of Exile 2\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PATHOFEXILE, NDPI_PROTOCOL_UNKNOWN,
                                 NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  /* The first packet always contains these signatures and the character's 
   * nickname (from 4 to 23 chars).
   */
  if ((packet->payload_packet_len > 25 && packet->payload_packet_len < 50) &&
      (packet->payload[0] == 0 && packet->payload[6] == 0))
  {
    if (ntohs(get_u_int16_t(packet->payload, 1)) == 0x300 &&
        ntohs(get_u_int16_t(packet->payload, 7)) == 0x200 &&
        ntohl(get_u_int32_t(packet->payload, packet->payload_packet_len-8)) == 0 &&
        ntohl(get_u_int32_t(packet->payload, packet->payload_packet_len-4)) == 0x40000001)
    {
      NDPI_LOG_INFO(ndpi_struct, "found Path of Exile\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PATHOFEXILE, NDPI_PROTOCOL_UNKNOWN,
                                 NDPI_CONFIDENCE_DPI);
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_pathofexile_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("PathofExile", ndpi_struct, *id,
              NDPI_PROTOCOL_PATHOFEXILE,
              ndpi_search_pathofexile,
              NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
              SAVE_DETECTION_BITMASK_AS_UNKNOWN,
              ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
