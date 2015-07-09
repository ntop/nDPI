/*
 * mssql.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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


#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_MSSQL

static void ndpi_int_mssql_add_connection(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MSSQL, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_mssql(struct ndpi_detection_module_struct
		       *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_MSSQL, ndpi_struct, NDPI_LOG_DEBUG, "search mssql.\n");

  if (packet->payload_packet_len > 51 && ntohs(get_u_int32_t(packet->payload, 0)) == 0x1201
      && ntohs(get_u_int16_t(packet->payload, 2)) == packet->payload_packet_len
      && ntohl(get_u_int32_t(packet->payload, 4)) == 0x00000100 && memcmp(&packet->payload[41], "sqlexpress", 10) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_MSSQL, ndpi_struct, NDPI_LOG_DEBUG, "found mssql.\n");
    ndpi_int_mssql_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_LOG(NDPI_PROTOCOL_MSSQL, ndpi_struct, NDPI_LOG_DEBUG, "exclude mssql.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MSSQL);
}


void init_mssql_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("MsSQL", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MSSQL,
				      ndpi_search_mssql,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
