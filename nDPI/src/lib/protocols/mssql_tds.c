/*
 * mssql.c
 *
 * Copyright (C) 2016 - ntop.org
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

#ifdef NDPI_PROTOCOL_MSSQL_TDS

struct tds_packet_header {
  u_int8_t type;
  u_int8_t status;
  u_int16_t length;
  u_int16_t channel;
  u_int8_t number;
  u_int8_t window;
};

static void ndpi_int_mssql_tds_add_connection(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MSSQL_TDS, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_mssql_tds(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  struct tds_packet_header *h = (struct tds_packet_header*) packet->payload;

  if(packet->payload_packet_len < sizeof(struct tds_packet_header)) {
    NDPI_LOG(NDPI_PROTOCOL_MSSQL_TDS, ndpi_struct, NDPI_LOG_DEBUG, "exclude mssql_tds\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MSSQL_TDS);
    return;
  }
  
  if((h->type >= 1 && h->type <= 8) || (h->type >= 14 && h->type <= 18)) {
    if(h->status == 0x00 || h->status == 0x01 || h->status == 0x02 || h->status == 0x04 || h->status == 0x08 || h->status == 0x09 || h->status == 0x10) {
      if(ntohs(h->length) == packet->payload_packet_len && h->window == 0x00) {
	NDPI_LOG(NDPI_PROTOCOL_MSSQL_TDS, ndpi_struct, NDPI_LOG_DEBUG, "found mssql_tds\n");
	ndpi_int_mssql_tds_add_connection(ndpi_struct, flow);
	return;
      }
    }
  }
  
  NDPI_LOG(NDPI_PROTOCOL_MSSQL_TDS, ndpi_struct, NDPI_LOG_DEBUG, "exclude mssql_tds\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MSSQL_TDS);
}


void init_mssql_tds_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("MsSQL_TDS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MSSQL_TDS,
				      ndpi_search_mssql_tds,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
