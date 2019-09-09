/*
 * imo.c
 *
 * Copyright (C) 2019 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_IMO

#include "ndpi_api.h"

static void ndpi_int_imo_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_IMO, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_imo(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search IMO\n");

  if(packet->payload_packet_len == 1) {
    /* Two one byte consecutive packets with the same payload */ 
    if((flow->protos.imo.last_one_byte_pkt == 1)
       && (flow->protos.imo.last_byte == packet->payload[0]))
      ndpi_int_imo_add_connection(ndpi_struct, flow);
    else
      flow->protos.imo.last_one_byte_pkt = 1, flow->protos.imo.last_byte = packet->payload[0];
  } else if(((packet->payload_packet_len == 10)
	 && (packet->payload[0] == 0x09)
	 && (packet->payload[1] == 0x02))
     || ((packet->payload_packet_len == 11)
	 && (packet->payload[0] == 0x00)
	 && (packet->payload[1] == 0x09)
	 && (packet->payload[2] == 0x03))
     || ((packet->payload_packet_len == 1099)
	 && (packet->payload[0] == 0x88)
	 && (packet->payload[1] == 0x49)
	 && (packet->payload[2] == 0x1a)
	 && (packet->payload[3] == 0x00))) {
    NDPI_LOG_INFO(ndpi_struct, "found IMO\n");
    ndpi_int_imo_add_connection(ndpi_struct, flow);
  } else {
    if(flow->num_processed_pkts > 7)
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    else
      flow->protos.imo.last_one_byte_pkt = 0;
  }
}


void init_imo_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("IMO", ndpi_struct, detection_bitmask, *id,
                                      NDPI_PROTOCOL_IMO,
                                      ndpi_search_imo,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

