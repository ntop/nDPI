/*
 * guildwars2.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_GUILDWARS2

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_guildwars2_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Guild Wars 2\n");

  if (packet->payload_packet_len > 50)
  {
    /* The connection starts with this preamble containing client info.
     * The TLS handshake begins around packet 12. */
    if ((memcmp(packet->payload, "P /Sts/Connect STS/1.0", 22) == 0) ||
        (memcmp(packet->payload, "P /Auth/StartTls STS/1.0", 24) == 0) ||
        (memcmp(packet->payload, "STS/1.0 400 Success", 19) == 0))
    {
      NDPI_LOG_INFO(ndpi_struct, "found Guild Wars 2\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_GUILDWARS2, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}


void init_guildwars2_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("GuildWars2", ndpi_struct,
                     ndpi_search_guildwars2_tcp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_GUILDWARS2);
}
