/*
 * netease_games.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NETEASE_GAMES

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_netease_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
                                            struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found NetEase Games\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NETEASE_GAMES,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_netease(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  /* I've seen this pattern in traffic of few games from 
   * NetEase (Lost Light, Badlanders, Naraka: Bladepoint) */

  if (packet->payload_packet_len == 12 &&
      current_pkt_from_client_to_server(ndpi_struct, flow) &&
      packet->payload[0] == 0x01 &&
      le16toh(get_u_int16_t(packet->payload, 2)) == 0x1D0 &&
      le32toh(get_u_int32_t(packet->payload, 8)) == 0x1010100)
  {
    ndpi_int_netease_add_connection(ndpi_struct, flow);
    return;
  }

  /* Lost Light */
  if (packet->payload_packet_len >= 30 && 
      ntohl(get_u_int32_t(packet->payload, 0)) == 0xB3AF8DE8)
  {
    ndpi_int_netease_add_connection(ndpi_struct, flow);
    return;
  }

  /* Naraka: Bladepoint */
  if (packet->payload_packet_len > 30 &&
      le32toh(get_u_int32_t(packet->payload, 0)) == 0x0C080807)
  {
    ndpi_int_netease_add_connection(ndpi_struct, flow);
    return;
  }

  /* TODO: add more NetEase Games signatures */

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_netease_games_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                  u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("NetEaseGames", ndpi_struct, *id,
                                      NDPI_PROTOCOL_NETEASE_GAMES,
                                      ndpi_search_netease,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
