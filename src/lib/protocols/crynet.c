/*
 * crynet.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CRYNET

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_crynet_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                           struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found CryNetwork\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_CRYNET,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_crynet(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search CryNetwork\n");

  if (packet->payload_packet_len <= 4)
  {
    if (flow->packet_counter == 1 && ntohs(packet->udp->dest) != 61088) {
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
      return;
    }

    size_t i;

    for (i = 0; i < packet->payload_packet_len; ++i) {
      if (ndpi_isdigit(packet->payload[i]) == 0) {
        NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
        return;
      }
    }

    if (flow->packet_counter >= 10) {
      ndpi_int_crynet_add_connection(ndpi_struct, flow);
      return;
    }

    return;
  }

  if (packet->payload_packet_len < 30)
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if (packet->payload_packet_len != packet->payload[0] + 10 &&
      packet->payload_packet_len != packet->payload[4] + 6)
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if (packet->payload[0] == 0x3c &&
      packet->payload[16] == 0x01 &&
      packet->payload[20] == 0x07 &&
      ntohs(get_u_int16_t(packet->payload, 24)) == 0x0307)
  {
    ndpi_int_crynet_add_connection(ndpi_struct, flow);
    return;
  }

  if (packet->payload[0] == 0x05 &&
      packet->payload[4] == 0x44 &&
      packet->payload[24] == 0x07 &&
      ntohs(get_u_int16_t(packet->payload, 28)) == 0x0307)
  {
    ndpi_int_crynet_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_crynet_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("CryNetwork", ndpi_struct,
                     ndpi_search_crynet,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                     1, NDPI_PROTOCOL_CRYNET);
}
