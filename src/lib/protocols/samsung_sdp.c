/*
 * samsung_sdp.c
 *
 * Copyright (C) 2025 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SAMSUNG_SDP

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_samsung_sdp_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                                struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Samsung Service Discovery Protocol\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_SAMSUNG_SDP,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_samsung_sdp(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Samsung Service Discovery Protocol\n");

  if (packet->payload_packet_len < NDPI_STATICSTRING_LEN("SEARCH BSDP/")) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if (memcmp(packet->payload, "SEARCH BSDP/", NDPI_STATICSTRING_LEN("SEARCH BSDP/")) != 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  ndpi_int_samsung_sdp_add_connection(ndpi_struct, flow);
}

void init_samsung_sdp_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("SamsungSDP", ndpi_struct,
                     ndpi_search_samsung_sdp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                     1, NDPI_PROTOCOL_SAMSUNG_SDP);
}

