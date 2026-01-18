/*
 * glbp.c
 *
 * Gateway Load Balancing Protocol
 * 
 * Copyright (C) 2025 - ntop.org
 * Copyright (C) 2025 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_GLBP

#include "ndpi_api.h"
#include "ndpi_private.h"

#define GLBP_PORT 3222 /* IANA registered */

static void ndpi_int_glbp_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                         struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found GLBP\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_GLBP, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_glbp(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search GLBP\n");

  if (packet->payload_packet_len < 12) {
    goto exclude;
  }

  if ((packet->udp->source != htons(GLBP_PORT)) || 
      (packet->udp->dest != htons(GLBP_PORT)))
  {
    goto exclude;
  }

  if ((packet->payload[0] > 1) ||
      (ntohs(get_u_int16_t(packet->payload, 2)) > 1023))
  {
    goto exclude;
  }

  ndpi_int_glbp_add_connection(ndpi_struct, flow);
  return;

exclude:
  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_glbp_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("GLBP", ndpi_struct,
                     ndpi_search_glbp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                     1, NDPI_PROTOCOL_GLBP);
}
