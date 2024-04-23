/*
 * iqiyi.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_IQIYI

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_iqiyi_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
                                          struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found iQIYI\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_IQIYI,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_iqiyi(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search iQIYI\n");

  if (packet->payload_packet_len > 120 && packet->payload_packet_len < 300) {
    if (ndpi_memmem(packet->payload, packet->payload_packet_len, "PPStream", NDPI_STATICSTRING_LEN("PPStream"))) {
      ndpi_int_iqiyi_add_connection(ndpi_struct, flow);
      return;
    }
  }

  /* Add more iQiyi signatures */

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_iqiyi_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                         u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("iQIYI", ndpi_struct, *id,
                                      NDPI_PROTOCOL_IQIYI,
                                      ndpi_search_iqiyi,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
