/*
 * teso.c
 *
 * The Elder Scrolls Online
 * 
 * Copyright (C) 2024 - ntop.org
 * Copyright (C) 2024 - V.G <jacendi@protonmail.com>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TESO

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_teso(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search TES Online\n");

  if (packet->payload_packet_len < 600 ||
      ntohl(get_u_int32_t(packet->payload, 0)) != (u_int32_t)(packet->payload_packet_len-4))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * I'd like to use just memcmp and a couple ifs here, but the offset to 
   * the string "eso.live" or the 0x8B789C01 byte sequence can be different - 
   * it varies by the amount of characters in the account name, weather on Mars,
   * etc.
   */

  const u_int8_t magic[] = { 0x8B, 0x78, 0x9C, 0x01 };

  if (memmem(packet->payload, 140, "eso.live", NDPI_STATICSTRING_LEN("eso.live"))) {
    NDPI_LOG_INFO(ndpi_struct, "found TES Online\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TESO,
                               NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }
  else if (memmem(packet->payload, 140, magic, sizeof(magic))) {
    NDPI_LOG_INFO(ndpi_struct, "found TES Online\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TESO,
                               NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_teso_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("TES_Online", ndpi_struct, *id,
              NDPI_PROTOCOL_TESO,
              ndpi_search_teso,
              NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
              SAVE_DETECTION_BITMASK_AS_UNKNOWN,
              ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
