/*
 * socrates.c
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
#ifdef NDPI_PROTOCOL_SOCRATES


static void ndpi_socrates_add_connection(struct ndpi_detection_module_struct
										   *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SOCRATES, NDPI_REAL_PROTOCOL);
}

void ndpi_search_socrates(struct ndpi_detection_module_struct
							*ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;



	NDPI_LOG(NDPI_PROTOCOL_SOCRATES, ndpi_struct, NDPI_LOG_DEBUG, "search socrates.\n");
	if (packet->udp != NULL) {
		if (packet->payload_packet_len > 9 && packet->payload[0] == 0xfe
			&& packet->payload[packet->payload_packet_len - 1] == 0x05) {
			NDPI_LOG(NDPI_PROTOCOL_SOCRATES, ndpi_struct, NDPI_LOG_DEBUG, "found fe.\n");

			NDPI_LOG(NDPI_PROTOCOL_SOCRATES, ndpi_struct, NDPI_LOG_DEBUG, "len match.\n");
			if (memcmp(&packet->payload[2], "socrates", 8) == 0) {
				NDPI_LOG(NDPI_PROTOCOL_SOCRATES, ndpi_struct, NDPI_LOG_DEBUG, "found socrates udp.\n");
				ndpi_socrates_add_connection(ndpi_struct, flow);
			}

		}
	} else if (packet->tcp != NULL) {
		if (packet->payload_packet_len > 13 && packet->payload[0] == 0xfe
			&& packet->payload[packet->payload_packet_len - 1] == 0x05) {
			NDPI_LOG(NDPI_PROTOCOL_SOCRATES, ndpi_struct, NDPI_LOG_DEBUG, "found fe.\n");
			if (packet->payload_packet_len == ntohl(get_u_int32_t(packet->payload, 2))) {
				NDPI_LOG(NDPI_PROTOCOL_SOCRATES, ndpi_struct, NDPI_LOG_DEBUG, "len match.\n");
				if (memcmp(&packet->payload[6], "socrates", 8) == 0) {
					NDPI_LOG(NDPI_PROTOCOL_SOCRATES, ndpi_struct, NDPI_LOG_DEBUG, "found socrates tcp.\n");
					ndpi_socrates_add_connection(ndpi_struct, flow);
				}
			}
		}
	}




	NDPI_LOG(NDPI_PROTOCOL_SOCRATES, ndpi_struct, NDPI_LOG_DEBUG, "exclude socrates.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOCRATES);
}

#endif
