/*
 * i3d.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_I3D

#include "ndpi_api.h"

static void ndpi_int_i3d_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                        struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found i3D\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_PROTOCOL_I3D,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_i3d(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "searching i3D\n");

  /*
   * i3D offers a lot of services.
   * The patterns below are mostly used by dedicated game servers.
   */

  if (packet->payload_packet_len < 74)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if ((ntohl(get_u_int32_t(packet->payload, 0)) == 0x00010046 ||
       ntohl(get_u_int32_t(packet->payload, 0)) == 0x00020046) &&
      ntohl(get_u_int32_t(packet->payload, 4)) == 0x0003cfa8)
  {
    ndpi_int_i3d_add_connection(ndpi_struct, flow);
    return;
  }

  if ((ntohs(get_u_int16_t(packet->payload, 0)) == 0x9078 ||
       ntohs(get_u_int16_t(packet->payload, 0)) == 0x9067) &&
      ntohl(get_u_int32_t(packet->payload, 8)) == 0x0003cfa9 &&
      ntohl(get_u_int32_t(packet->payload, 12)) == 0xbede0003)
  {
    ndpi_int_i3d_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  return;
}

void init_i3d_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                        u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("i3D", ndpi_struct, *id,
    NDPI_PROTOCOL_I3D,
    ndpi_search_i3d,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );

  *id += 1;
}
