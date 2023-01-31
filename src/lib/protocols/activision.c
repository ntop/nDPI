/*
 * activision.c
 *
 * Copyright (C) 2022-23 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ACTIVISION

#include "ndpi_api.h"

static void ndpi_int_activision_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                               struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found activision\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_ACTIVISION,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_activision(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search activision\n");

  if (packet->payload_packet_len < 18)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (flow->packet_direction_counter[packet->packet_direction] == 1)
  {
    if (packet->packet_direction == 0)
    {
      if (ntohs(get_u_int16_t(packet->payload, 0)) != 0x0c02)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }
    } else {
      if (ntohs(get_u_int16_t(packet->payload, 0)) != 0x0d02)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }
    }

    if (packet->payload_packet_len < 29)
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    if (ntohs(get_u_int16_t(packet->payload, 17)) == 0xc0a8 &&
        ntohl(get_u_int32_t(packet->payload, 19)) == 0x0015020c)
    {
      ndpi_int_activision_add_connection(ndpi_struct, flow);
      return;
    }
  } else if (packet->packet_direction == 0) {
    if (packet->payload[0] != 0x29)
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
  } else if (packet->packet_direction == 1) {
    if (packet->payload[0] != 0x28)
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
  }

  if (flow->packet_counter > 4)
  {
    ndpi_int_activision_add_connection(ndpi_struct, flow);
  }
}

void init_activision_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                             u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Activision", ndpi_struct, *id,
    NDPI_PROTOCOL_ACTIVISION,
    ndpi_search_activision,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );

  *id += 1;
}
