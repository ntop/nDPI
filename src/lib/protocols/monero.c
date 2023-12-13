/*
 * monero.c
 *
 * Copyright (C) 2023 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MONERO

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_monero_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                           struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Monero Protocol\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_MONERO, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);

  if(ndpi_struct->mining_cache)
  {
    ndpi_lru_add_to_cache(ndpi_struct->mining_cache,
                          mining_make_lru_cache_key(flow),
                          NDPI_PROTOCOL_MONERO,
                          ndpi_get_current_time(flow));
  }
}

static void ndpi_search_monero(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Monero Protocol\n");

  if (packet->payload_packet_len < 8)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (get_u_int64_t(packet->payload, 0) == ndpi_htonll(0x0121010101010101))
  {
    ndpi_int_monero_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_monero_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Monero", ndpi_struct, *id,
                                      NDPI_PROTOCOL_MONERO,
                                      ndpi_search_monero,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
