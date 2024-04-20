/*
 * mumble.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MUMBLE

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_mumble(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Mumble\n");

  if (current_pkt_from_client_to_server(ndpi_struct, flow) && 
      packet->payload_packet_len == 12)
  {
    if (get_u_int32_t(packet->payload, 0) == 0) {
      flow->l4.udp.mumble_stage = 1;
      flow->l4.udp.mumble_ident = ndpi_ntohll(get_u_int64_t(packet->payload, 4));
      return;
    }
    goto not_mumble;
  }

  if (flow->l4.udp.mumble_stage == 1 && packet->payload_packet_len == 24) {
    if (ndpi_ntohll(get_u_int64_t(packet->payload, 4)) == flow->l4.udp.mumble_ident) {
      NDPI_LOG_INFO(ndpi_struct, "found Mumble\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MUMBLE,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
    goto not_mumble;
  }

not_mumble:
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_mumble_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Mumble", ndpi_struct, *id,
                                      NDPI_PROTOCOL_MUMBLE,
                                      ndpi_search_mumble,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
