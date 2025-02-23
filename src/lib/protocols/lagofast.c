/*
 * lagofast.c
 *
 * Copyright (C) 2011-25 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_LAGOFAST

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_lagofast_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                             struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found LagoFast\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_LAGOFAST,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_lagofast(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search LagoFast\n");
  if (packet->payload_packet_len < 6) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  // LagoFast identifier
  if (get_u_int32_t(packet->payload, 0) != htonl(0x006e5d03)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  // Check encoded length
  const uint16_t encoded_length = ntohs(get_u_int16_t(packet->payload, 4));
  if (packet->payload_packet_len != encoded_length + 6 /* identifier + length */) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_lagofast_add_connection(ndpi_struct, flow);
}

void init_lagofast_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                             u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("LagoFast", ndpi_struct, *id,
				      NDPI_PROTOCOL_LAGOFAST,
				      ndpi_search_lagofast,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

