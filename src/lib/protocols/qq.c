/*
 * qq.c
 *
 * Copyright (C) 2009-2011
 * Copyright (C) 2011-18 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_QQ

#include "ndpi_api.h"


static void ndpi_int_qq_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow/* , */
				       /* ndpi_protocol_type_t protocol_type */)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QQ, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_qq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search QQ\n");

  if ((packet->payload_packet_len == 72 && ntohl(get_u_int32_t(packet->payload, 0)) == 0x02004800) ||
      (packet->payload_packet_len == 64 && ntohl(get_u_int32_t(packet->payload, 0)) == 0x02004000) ||
      (packet->payload_packet_len == 60 && ntohl(get_u_int32_t(packet->payload, 0)) == 0x02004200) ||
      (packet->payload_packet_len == 84 && ntohl(get_u_int32_t(packet->payload, 0)) == 0x02005a00) ||
      (packet->payload_packet_len == 56 && ntohl(get_u_int32_t(packet->payload, 0)) == 0x02003800) ||
      (packet->payload_packet_len >= 39 && ntohl(get_u_int32_t(packet->payload, 0)) == 0x28000000)) {
        NDPI_LOG_INFO(ndpi_struct, "found QQ\n");
        ndpi_int_qq_add_connection(ndpi_struct, flow);
      } else {
        if(flow->num_processed_pkts > 4)
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      }
}


void init_qq_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
                       NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("QQ", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_QQ,
				      ndpi_search_qq,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
