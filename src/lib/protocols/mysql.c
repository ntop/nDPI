/*
 * mysql.c
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
#ifdef NDPI_PROTOCOL_MYSQL

static void ndpi_int_mysql_add_connection(struct ndpi_detection_module_struct
											*ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MYSQL, NDPI_REAL_PROTOCOL);
}

void ndpi_search_mysql_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (packet->payload_packet_len > 37	//min length
		&& get_u_int16_t(packet->payload, 0) == packet->payload_packet_len - 4	//first 3 bytes are length
		&& get_u_int8_t(packet->payload, 2) == 0x00	//3rd byte of packet length
		&& get_u_int8_t(packet->payload, 3) == 0x00	//packet sequence number is 0 for startup packet
		&& get_u_int8_t(packet->payload, 5) > 0x30	//server version > 0
		&& get_u_int8_t(packet->payload, 5) < 0x37	//server version < 7
		&& get_u_int8_t(packet->payload, 6) == 0x2e	//dot
		) {
		u_int32_t a;
		for (a = 7; a + 31 < packet->payload_packet_len; a++) {
			if (packet->payload[a] == 0x00) {
				if (get_u_int8_t(packet->payload, a + 13) == 0x00	//filler byte
					&& get_u_int64_t(packet->payload, a + 19) == 0x0ULL	//13 more
					&& get_u_int32_t(packet->payload, a + 27) == 0x0	//filler bytes
					&& get_u_int8_t(packet->payload, a + 31) == 0x0) {
					NDPI_LOG(NDPI_PROTOCOL_MYSQL, ndpi_struct, NDPI_LOG_DEBUG, "MySQL detected.\n");
					ndpi_int_mysql_add_connection(ndpi_struct, flow);
					return;
				}
				break;
			}
		}
	}

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MYSQL);

}

#endif
