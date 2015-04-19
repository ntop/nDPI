/*
 * postgres.c
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
#ifdef NDPI_PROTOCOL_POSTGRES


static void ndpi_int_postgres_add_connection(struct ndpi_detection_module_struct
											   *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_POSTGRES, NDPI_REAL_PROTOCOL);
}

void ndpi_search_postgres_tcp(struct ndpi_detection_module_struct
								*ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	u_int16_t size;

	if (flow->l4.tcp.postgres_stage == 0) {
		//SSL
		if (packet->payload_packet_len > 7 &&
			packet->payload[4] == 0x04 &&
			packet->payload[5] == 0xd2 &&
			packet->payload[6] == 0x16 &&
			packet->payload[7] == 0x2f && ntohl(get_u_int32_t(packet->payload, 0)) == packet->payload_packet_len) {
			flow->l4.tcp.postgres_stage = 1 + packet->packet_direction;
			return;
		}
		//no SSL
		if (packet->payload_packet_len > 7 &&
			//protocol version number - to be updated
			ntohl(get_u_int32_t(packet->payload, 4)) < 0x00040000 &&
			ntohl(get_u_int32_t(packet->payload, 0)) == packet->payload_packet_len) {
			flow->l4.tcp.postgres_stage = 3 + packet->packet_direction;
			return;
		}
	} else {
		if (flow->l4.tcp.postgres_stage == 2 - packet->packet_direction) {
			//SSL accepted
			if (packet->payload_packet_len == 1 && packet->payload[0] == 'S') {
				NDPI_LOG(NDPI_PROTOCOL_POSTGRES, ndpi_struct, NDPI_LOG_DEBUG, "PostgreSQL detected, SSL accepted.\n");
				ndpi_int_postgres_add_connection(ndpi_struct, flow);
				return;
			}
			//SSL denied
			if (packet->payload_packet_len == 1 && packet->payload[0] == 'N') {
				NDPI_LOG(NDPI_PROTOCOL_POSTGRES, ndpi_struct, NDPI_LOG_DEBUG, "PostgreSQL detected, SSL denied.\n");
				ndpi_int_postgres_add_connection(ndpi_struct, flow);
				return;
			}
		}
		//no SSL
		if (flow->l4.tcp.postgres_stage == 4 - packet->packet_direction)
			if (packet->payload_packet_len > 8 &&
				ntohl(get_u_int32_t(packet->payload, 5)) < 10 &&
				ntohl(get_u_int32_t(packet->payload, 1)) == packet->payload_packet_len - 1 && packet->payload[0] == 0x52) {
				NDPI_LOG(NDPI_PROTOCOL_POSTGRES, ndpi_struct, NDPI_LOG_DEBUG, "PostgreSQL detected, no SSL.\n");
				ndpi_int_postgres_add_connection(ndpi_struct, flow);
				return;
			}
		if (flow->l4.tcp.postgres_stage == 6
			&& ntohl(get_u_int32_t(packet->payload, 1)) == packet->payload_packet_len - 1 && packet->payload[0] == 'p') {
			NDPI_LOG(NDPI_PROTOCOL_POSTGRES, ndpi_struct, NDPI_LOG_DEBUG, "found postgres asymmetrically.\n");
			ndpi_int_postgres_add_connection(ndpi_struct, flow);
			return;
		}
		if (flow->l4.tcp.postgres_stage == 5 && packet->payload[0] == 'R') {
			if (ntohl(get_u_int32_t(packet->payload, 1)) == packet->payload_packet_len - 1) {
				NDPI_LOG(NDPI_PROTOCOL_POSTGRES, ndpi_struct, NDPI_LOG_DEBUG, "found postgres asymmetrically.\n");
				ndpi_int_postgres_add_connection(ndpi_struct, flow);
				return;
			}
			size = (u_int16_t)ntohl(get_u_int32_t(packet->payload, 1)) + 1;
			if (packet->payload[size - 1] == 'S') {
				if ((size + get_u_int32_t(packet->payload, (size + 1))) == packet->payload_packet_len) {
					NDPI_LOG(NDPI_PROTOCOL_POSTGRES, ndpi_struct, NDPI_LOG_DEBUG, "found postgres asymmetrically.\n");
					ndpi_int_postgres_add_connection(ndpi_struct, flow);
					return;
				}
			}
			size += get_u_int32_t(packet->payload, (size + 1)) + 1;
			if (packet->payload[size - 1] == 'S') {
				NDPI_LOG(NDPI_PROTOCOL_POSTGRES, ndpi_struct, NDPI_LOG_DEBUG, "found postgres asymmetrically.\n");
				ndpi_int_postgres_add_connection(ndpi_struct, flow);
				return;
			}
		}
	}

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_POSTGRES);
}

#endif
