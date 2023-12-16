/*
 * profinet_io.c
 *
 * Copyright (C) 2023 - ntop.org
 * Copyright (C) 2023 - V.G <jacendi@protonmail.com>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_PROFINET_IO

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_profinet_io_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                                struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found PROFINET/IO\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_PROFINET_IO, NDPI_PROTOCOL_DCERPC,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_profinet_io(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "searching PROFINET/IO\n");

  /* PROFINET/IO is based on connectionless DCE/RPC */
  if ((flow->detected_protocol_stack[0] == NDPI_PROTOCOL_DCERPC) &&
      (packet->udp != NULL) && (packet->payload_packet_len > 43))
  {
    u_int64_t object_uuid = 0;

    if ((packet->payload[4] >> 4) & 0xF) {
      object_uuid = le64toh(get_u_int64_t(packet->payload, 8));
    } else {
      object_uuid = ndpi_ntohll(get_u_int64_t(packet->payload, 8));
    }

    if (object_uuid = 0xDEA00006C9711D1) {
      ndpi_int_profinet_io_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_profinet_io_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("PROFINET_IO", ndpi_struct, *id,
                                      NDPI_PROTOCOL_PROFINET_IO,
                                      ndpi_search_profinet_io,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK
                                     );

  *id += 1;
}
