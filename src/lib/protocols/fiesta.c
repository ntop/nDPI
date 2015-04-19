/*
 * fiesta.c
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



/* include files */
#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_FIESTA


static void ndpi_int_fiesta_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FIESTA, NDPI_REAL_PROTOCOL);
}

void ndpi_search_fiesta(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	NDPI_LOG(NDPI_PROTOCOL_FIESTA, ndpi_struct, NDPI_LOG_DEBUG, "search fiesta.\n");

	if (flow->l4.tcp.fiesta_stage == 0 && packet->payload_packet_len == 5
		&& get_u_int16_t(packet->payload, 0) == ntohs(0x0407)
		&& (packet->payload[2] == 0x08)
		&& (packet->payload[4] == 0x00 || packet->payload[4] == 0x01)) {

		NDPI_LOG(NDPI_PROTOCOL_FIESTA, ndpi_struct, NDPI_LOG_DEBUG, "maybe fiesta symmetric, first packet.\n");
		flow->l4.tcp.fiesta_stage = 1 + packet->packet_direction;
		goto maybe_fiesta;
	}
	if (flow->l4.tcp.fiesta_stage == (2 - packet->packet_direction)
		&& ((packet->payload_packet_len > 1 && packet->payload_packet_len - 1 == packet->payload[0])
			|| (packet->payload_packet_len > 3 && packet->payload[0] == 0
				&& get_l16(packet->payload, 1) == packet->payload_packet_len - 3))) {
		NDPI_LOG(NDPI_PROTOCOL_FIESTA, ndpi_struct, NDPI_LOG_DEBUG, "Maybe fiesta.\n");
		goto maybe_fiesta;
	}
	if (flow->l4.tcp.fiesta_stage == (1 + packet->packet_direction)) {
		if (packet->payload_packet_len == 4 && get_u_int32_t(packet->payload, 0) == htonl(0x03050c01)) {
			goto add_fiesta;
		}
		if (packet->payload_packet_len == 5 && get_u_int32_t(packet->payload, 0) == htonl(0x04030c01)
			&& packet->payload[4] == 0) {
			goto add_fiesta;
		}
		if (packet->payload_packet_len == 6 && get_u_int32_t(packet->payload, 0) == htonl(0x050e080b)) {
			goto add_fiesta;
		}
		if (packet->payload_packet_len == 100 && packet->payload[0] == 0x63 && packet->payload[61] == 0x52
			&& packet->payload[81] == 0x5a && get_u_int16_t(packet->payload, 1) == htons(0x3810)
			&& get_u_int16_t(packet->payload, 62) == htons(0x6f75)) {
			goto add_fiesta;
		}
		if (packet->payload_packet_len > 3 && packet->payload_packet_len - 1 == packet->payload[0]
			&& get_u_int16_t(packet->payload, 1) == htons(0x140c)) {
			goto add_fiesta;
		}
	}

	NDPI_LOG(NDPI_PROTOCOL_FIESTA, ndpi_struct, NDPI_LOG_DEBUG, "exclude fiesta.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FIESTA);
	return;

  maybe_fiesta:
	NDPI_LOG(NDPI_PROTOCOL_FIESTA, ndpi_struct, NDPI_LOG_DEBUG, "Stage is set to %d.\n", flow->l4.tcp.fiesta_stage);
	return;

  add_fiesta:
	NDPI_LOG(NDPI_PROTOCOL_FIESTA, ndpi_struct, NDPI_LOG_DEBUG, "detected fiesta.\n");
	ndpi_int_fiesta_add_connection(ndpi_struct, flow);
	return;
}
#endif
