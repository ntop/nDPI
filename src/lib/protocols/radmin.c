/*
 * radmin.c
 *
 * Copyright (C) 2024 - ntop.org
 * Copyright (C) 2024 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RADMIN

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_radmin_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                           struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Radmin\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_RADMIN, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found Radmin");
}

static void ndpi_search_radmin(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Radmin\n");

  if (current_pkt_from_client_to_server(ndpi_struct, flow) && packet->payload_packet_len == 10 &&
      !flow->l4.tcp.radmin_stage)
  {
    if (ntohl(get_u_int32_t(packet->payload, 0)) == 0x1000000 && 
        packet->payload[4] == 1 &&
        ntohs(get_u_int16_t(packet->payload, 8) == 0x808))
    {
      flow->l4.tcp.radmin_stage = 1;
      return;
    }
  }

  if (current_pkt_from_server_to_client(ndpi_struct, flow) && packet->payload_packet_len == 46 &&
      flow->l4.tcp.radmin_stage)
  {
    if (ntohl(get_u_int32_t(packet->payload, 0)) == 0x1000000 &&
        packet->payload[4] == 0x25 &&
        ntohl(get_u_int32_t(packet->payload, 7)) == 0x2120802 &&
        packet->payload[13] == 0x0A)
    {
      ndpi_int_radmin_add_connection(ndpi_struct, flow);
      return;
    }
  }

  if (packet->payload_packet_len == 14 && 
      ntohl(get_u_int32_t(packet->payload, 0)) == 0x1000000 &&
      packet->payload[4] == 5 && 
      ntohs(get_u_int16_t(packet->payload, 8)) == 0x2727)
  {
    if (!flow->l4.tcp.radmin_stage) {
      flow->l4.tcp.radmin_stage = 1;
      return;
    }

    ndpi_int_radmin_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_radmin_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Radmin", ndpi_struct, *id,
				      NDPI_PROTOCOL_RADMIN,
				      ndpi_search_radmin,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
