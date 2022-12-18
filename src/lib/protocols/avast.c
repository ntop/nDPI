/*
 * avast.c
 *
 * Copyright (C) 2012-22 - ntop.org
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_AVAST

#include <stdlib.h>
#include "ndpi_api.h"

static void ndpi_int_avast_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                          struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_AVAST, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_avast(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * packet = &ndpi_struct->packet;

  if (packet->payload_packet_len < 6)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (strncmp((char *)&packet->payload[0], "NOSA", NDPI_STATICSTRING_LEN("NOSA")) == 0 &&
      ntohs(*(uint16_t *)&packet->payload[4]) == packet->payload_packet_len)
  {
    ndpi_int_avast_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_avast_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("AVAST",
                                      ndpi_struct, *id,
                                      NDPI_PROTOCOL_AVAST,
                                      ndpi_search_avast,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
