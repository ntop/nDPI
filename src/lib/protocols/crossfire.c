/*
 * crossfire.c
 *
 * Copyright (C) 2012-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CROSSFIRE

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_crossfire_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
                                              struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found CrossFire\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CROSSFIRE, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_crossfire_tcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search CrossFire\n");


  if (packet->udp != NULL && packet->payload_packet_len >= 8 &&
      get_u_int32_t(packet->payload, 0) == ntohl(0xc7d91999))
  {
    ndpi_int_crossfire_add_connection(ndpi_struct, flow);
    return;
  }


  if (packet->tcp != NULL && packet->payload_packet_len > 100 &&
      (packet->payload[0] == 0xF1 && packet->payload[packet->payload_packet_len-1] == 0xF2))
  {
    /* Login packet */
    if (ntohl(get_u_int32_t(packet->payload, 2)) == 0x01000000)
    {
      ndpi_int_crossfire_add_connection(ndpi_struct, flow);
      return;
    }

    /* TODO: add more CrossFire TCP signatures*/
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}


void init_crossfire_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Crossfire", ndpi_struct,
                     ndpi_search_crossfire_tcp_udp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_CROSSFIRE);
}
