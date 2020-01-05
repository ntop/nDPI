/*
 * fiesta.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FIESTA

#include "ndpi_api.h"


static void ndpi_int_fiesta_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_FIESTA, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_fiesta(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG_DBG(ndpi_struct, "search fiesta\n");

	if (flow->l4.tcp.fiesta_stage == 0 && packet->payload_packet_len == 5
		&& get_u_int16_t(packet->payload, 0) == ntohs(0x0407)
		&& (packet->payload[2] == 0x08)
		&& (packet->payload[4] == 0x00 || packet->payload[4] == 0x01)) {

		NDPI_LOG_DBG2(ndpi_struct, "maybe fiesta symmetric, first packet\n");
		flow->l4.tcp.fiesta_stage = 1 + packet->packet_direction;
		goto maybe_fiesta;
	}
	if (flow->l4.tcp.fiesta_stage == (2 - packet->packet_direction)
		&& ((packet->payload_packet_len > 1 && packet->payload_packet_len - 1 == packet->payload[0])
			|| (packet->payload_packet_len > 3 && packet->payload[0] == 0
				&& get_l16(packet->payload, 1) == packet->payload_packet_len - 3))) {
		NDPI_LOG_DBG2(ndpi_struct, "Maybe fiesta\n");
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

	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	return;

  maybe_fiesta:
	NDPI_LOG_DBG2(ndpi_struct, "Stage is set to %d\n", flow->l4.tcp.fiesta_stage);
	return;

  add_fiesta:
	NDPI_LOG_INFO(ndpi_struct, "found fiesta\n");
	ndpi_int_fiesta_add_connection(ndpi_struct, flow);
	return;
}


void init_fiesta_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Fiesta", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_FIESTA,
				      ndpi_search_fiesta,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
