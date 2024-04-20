/*
 * rtps.c
 *
 * Real-Time Publish Subscribe Protocol
 * 
 * Copyright (C) 2023 - ntop.org
 * Copyright (C) 2023 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RTPS

#include "ndpi_api.h"
#include "ndpi_private.h"

/* Check https://www.omg.org/spec/DDSI-RTPS/ 
 * for updates
 */
#define RTPS_LAST_MAJOR_VER 2
#define RTPS_LAST_MINOR_VER 5

static void ndpi_search_rtps(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "searching RTPS\n");

  if (packet->payload_packet_len >= 16) {
    if (((memcmp(packet->payload, "RTPS", 4) == 0)    || 
         (memcmp(packet->payload, "RTPX", 4) == 0))   &&
        ((packet->payload[4] == RTPS_LAST_MAJOR_VER)  &&  
         (packet->payload[5] <= RTPS_LAST_MINOR_VER)))
    {
      NDPI_LOG_INFO(ndpi_struct, "found RTPS\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RTPS,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_rtps_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("RTPS", ndpi_struct, *id,
                                      NDPI_PROTOCOL_RTPS,
                                      ndpi_search_rtps,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK
                                     );

  *id += 1;
}
