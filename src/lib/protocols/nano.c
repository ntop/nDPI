/*
 * nano.c
 *
 * Nano Network Protocol
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NANO

#include "ndpi_api.h"
#include "ndpi_private.h"

/* 
 * Look for the latest version at https://docs.nano.org/releases/node-releases
 */
#define NANO_MIN_PROTOCOL_VER 18
#define NANO_MAX_PROTOCOL_VER 20

static void ndpi_int_nano_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                         struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Nano Network Protocol\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_NANO, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);

  if(ndpi_struct->mining_cache)
  {
    ndpi_lru_add_to_cache(ndpi_struct->mining_cache, mining_make_lru_cache_key(flow),
                          NDPI_PROTOCOL_NANO, ndpi_get_current_time(flow));
  }
}

static void ndpi_search_nano(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Nano Network Protocol\n");

  if (packet->payload_packet_len > 32 &&
      packet->payload[0] == 'R' && packet->payload[1] == 'C')
  {
    const u_int8_t max_ver = packet->payload[2];
    const u_int8_t use_ver = packet->payload[3];
    const u_int8_t min_ver = packet->payload[4];

    if (max_ver == NANO_MAX_PROTOCOL_VER &&
        use_ver <= NANO_MAX_PROTOCOL_VER && use_ver >= NANO_MIN_PROTOCOL_VER &&
        min_ver >= NANO_MIN_PROTOCOL_VER && min_ver < NANO_MAX_PROTOCOL_VER &&
        packet->payload[5] <= 0x0F)
    {
      ndpi_int_nano_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_nano_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Nano", ndpi_struct, *id,
                                      NDPI_PROTOCOL_NANO,
                                      ndpi_search_nano,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
