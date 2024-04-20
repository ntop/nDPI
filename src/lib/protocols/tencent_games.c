/*
 * tencent_games.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TENCENTGAMES

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_tencent_games_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
                                                  struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Tencent Games\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TENCENTGAMES,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_tencent_games(struct ndpi_detection_module_struct *ndpi_struct,
                                      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Tencent Games\n");

  if (packet->payload_packet_len > 50) {
    if (ntohl(get_u_int32_t(packet->payload, 0)) == 0x3366000B &&
        ntohs(get_u_int16_t(packet->payload, 4)) == 0xB)
    {
      ndpi_int_tencent_games_add_connection(ndpi_struct, flow);
      return;
    }

    if (ntohl(get_u_int32_t(packet->payload, 0)) == 0x4366AA00 &&
        ntohl(get_u_int32_t(packet->payload, 12)) == 0x10E68601)
    {
      ndpi_int_tencent_games_add_connection(ndpi_struct, flow);
      return;
    }

    if (ntohl(get_u_int32_t(packet->payload, 0)) == 0xAA000000 &&
        ntohl(get_u_int32_t(packet->payload, 10)) == 0x10E68601)
    {
      ndpi_int_tencent_games_add_connection(ndpi_struct, flow);
      return;
    }

    if (get_u_int16_t(packet->payload, 0) == 0 &&
        ntohs(get_u_int16_t(packet->payload, 2)) == (u_int16_t)(packet->payload_packet_len-4) &&
        ntohs(get_u_int16_t(packet->payload, 4)) == 0x7801)
    {
      ndpi_int_tencent_games_add_connection(ndpi_struct, flow);
      return;
    }

    if (ntohl(get_u_int32_t(packet->payload, 0)) == 0x4215F787 &&
        get_u_int16_t(packet->payload, 6) == 0)
    {
      ndpi_int_tencent_games_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_tencent_games_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("TencentGames", ndpi_struct, *id,
				      NDPI_PROTOCOL_TENCENTGAMES,
				      ndpi_search_tencent_games,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
