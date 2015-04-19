/*
 * dofus.c
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



#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_DOFUS

static void ndpi_dofus_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DOFUS, NDPI_REAL_PROTOCOL);
}

void ndpi_search_dofus(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;


	/* Dofus v 1.x.x */
	if (packet->payload_packet_len == 13 && get_u_int16_t(packet->payload, 1) == ntohs(0x0508)
		&& get_u_int16_t(packet->payload, 5) == ntohs(0x04a0)
		&& get_u_int16_t(packet->payload, packet->payload_packet_len - 2) == ntohs(0x0194)) {
		NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "found dofus.\n");
		ndpi_dofus_add_connection(ndpi_struct, flow);
		return;
	}
	if (flow->l4.tcp.dofus_stage == 0 && packet->payload_packet_len == 3 && memcmp(packet->payload, "HG", 2) == 0
		&& packet->payload[packet->payload_packet_len - 1] == 0) {
		flow->l4.tcp.dofus_stage = 1;
		NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "maybe dofus.\n");
		return;
	}
	if (flow->l4.tcp.dofus_stage == 0 && packet->payload_packet_len == 35 && memcmp(packet->payload, "HC", 2) == 0
		&& packet->payload[packet->payload_packet_len - 1] == 0) {
		flow->l4.tcp.dofus_stage = 1;
		NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "maybe dofus.\n");
		return;
	}
	if (flow->l4.tcp.dofus_stage == 0 && packet->payload_packet_len > 2 && packet->payload[0] == 'A'
		&& (packet->payload[1] == 'x' || packet->payload[1] == 'X')
		&& packet->payload[packet->payload_packet_len - 1] == 0) {
		flow->l4.tcp.dofus_stage = 1;
		NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "maybe dofus.\n");
		return;
	}
	if (flow->l4.tcp.dofus_stage == 0 && packet->payload_packet_len == 12 && memcmp(packet->payload, "Af", 2) == 0
		&& packet->payload[packet->payload_packet_len - 1] == 0) {
		flow->l4.tcp.dofus_stage = 1;
		NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "maybe dofus.\n");
		return;
	}
	if (flow->l4.tcp.dofus_stage == 0 && packet->payload_packet_len > 2 && memcmp(packet->payload, "Ad", 2)
		&& packet->payload[packet->payload_packet_len - 1] == 0) {
		flow->l4.tcp.dofus_stage = 1;
		NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "maybe dofus.\n");
		return;
	}
	if (packet->payload_packet_len == 11 && memcmp(packet->payload, "AT", 2) == 0 && packet->payload[10] == 0x00) {
		if (flow->l4.tcp.dofus_stage == 1) {
			NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "found dofus.\n");
			ndpi_dofus_add_connection(ndpi_struct, flow);
			return;
		}
	}
	if (flow->l4.tcp.dofus_stage == 1 && packet->payload_packet_len == 5
		&& packet->payload[0] == 'A' && packet->payload[4] == 0x00 && (packet->payload[1] == 'T'
																	   || packet->payload[1] == 'k')) {
		NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "found dofus asym.\n");
		ndpi_dofus_add_connection(ndpi_struct, flow);
		return;
	}
	/* end Dofus 1.x.x */


	/* Dofus 2.0 */
	if ((packet->payload_packet_len == 11 || packet->payload_packet_len == 13 || packet->payload_packet_len == 49)
		&& get_u_int32_t(packet->payload, 0) == ntohl(0x00050800)
		&& get_u_int16_t(packet->payload, 4) == ntohs(0x0005)
		&& get_u_int16_t(packet->payload, 8) == ntohs(0x0005)
		&& packet->payload[10] == 0x18) {
		if (packet->payload_packet_len == 13
			&& get_u_int16_t(packet->payload, packet->payload_packet_len - 2) != ntohs(0x0194)) {
			goto exclude;
		}
		if (packet->payload_packet_len == 49 && ntohs(get_u_int16_t(packet->payload, 15)) + 17 != packet->payload_packet_len) {
			goto exclude;
		}
		NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "found dofus.\n");
		ndpi_dofus_add_connection(ndpi_struct, flow);
		return;
	}
	if (packet->payload_packet_len >= 41 && get_u_int16_t(packet->payload, 0) == ntohs(0x01b9) && packet->payload[2] == 0x26) {
		u_int16_t len, len2;
		len = ntohs(get_u_int16_t(packet->payload, 3));
		if ((len + 5 + 2) > packet->payload_packet_len)
			goto exclude;
		len2 = ntohs(get_u_int16_t(packet->payload, 5 + len));
		if (5 + len + 2 + len2 == packet->payload_packet_len) {
			NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "found dofus.\n");
			ndpi_dofus_add_connection(ndpi_struct, flow);
			return;
		}
	}
	if (packet->payload_packet_len == 56
		&& memcmp(packet->payload, "\x00\x11\x35\x02\x03\x00\x93\x96\x01\x00", 10) == 0) {
		u_int16_t len, len2;
		len = ntohs(get_u_int16_t(packet->payload, 10));
		if ((len + 12 + 2) > packet->payload_packet_len)
			goto exclude;
		len2 = ntohs(get_u_int16_t(packet->payload, 12 + len));
		if ((12 + len + 2 + len2 + 1) > packet->payload_packet_len)
			goto exclude;
		if (12 + len + 2 + len2 + 1 == packet->payload_packet_len && packet->payload[12 + len + 2 + len2] == 0x01) {
			NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "found dofus.\n");
			ndpi_dofus_add_connection(ndpi_struct, flow);
			return;
		}
	}
  exclude:
	NDPI_LOG(NDPI_PROTOCOL_DOFUS, ndpi_struct, NDPI_LOG_DEBUG, "exclude dofus.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DOFUS);
}

#endif
