/*
 * popo.c
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
#ifdef NDPI_PROTOCOL_POPO

static void ndpi_int_popo_add_connection(struct ndpi_detection_module_struct
										   *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_POPO, NDPI_REAL_PROTOCOL);
}

void ndpi_search_popo_tcp_udp(struct ndpi_detection_module_struct
								*ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;

	if (packet->tcp != NULL) {
		if ((packet->payload_packet_len == 20)
			&& get_u_int32_t(packet->payload, 0) == htonl(0x0c000000)
			&& get_u_int32_t(packet->payload, 4) == htonl(0x01010000)
			&& get_u_int32_t(packet->payload, 8) == htonl(0x06000000)
			&& get_u_int32_t(packet->payload, 12) == 0 && get_u_int32_t(packet->payload, 16) == 0) {
			NDPI_LOG(NDPI_PROTOCOL_POPO, ndpi_struct, NDPI_LOG_DEBUG, "POPO detected\n");
			ndpi_int_popo_add_connection(ndpi_struct, flow);
			return;
		}

		if (NDPI_SRC_OR_DST_HAS_PROTOCOL(src, dst, NDPI_PROTOCOL_POPO) != 0) {
#define NDPI_POPO_IP_SUBNET_START ( (220 << 24) + (181 << 16) + (28 << 8) + 220)
#define NDPI_POPO_IP_SUBNET_END ( (220 << 24) + (181 << 16) + (28 << 8) + 238)

			/* may match the first payload ip packet only ... */

			if (ntohl(packet->iph->daddr) >= NDPI_POPO_IP_SUBNET_START
				&& ntohl(packet->iph->daddr) <= NDPI_POPO_IP_SUBNET_END) {
				NDPI_LOG(NDPI_PROTOCOL_POPO, ndpi_struct, NDPI_LOG_DEBUG, "POPO ip subnet detected\n");
				ndpi_int_popo_add_connection(ndpi_struct, flow);
				return;
			}
		}
	}

	if (packet->payload_packet_len > 13 && packet->payload_packet_len == get_l32(packet->payload, 0)
		&& !get_l16(packet->payload, 12)) {
		register u_int16_t ii;
		for (ii = 14; ii < 50 && ii < packet->payload_packet_len - 8; ++ii) {
			if (packet->payload[ii] == '@')
				if (!memcmp(&packet->payload[ii + 1], "163.com", 7)
					|| (ii <= packet->payload_packet_len - 13 && !memcmp(&packet->payload[ii + 1], "popo.163.com", 12))) {
					NDPI_LOG(NDPI_PROTOCOL_POPO, ndpi_struct, NDPI_LOG_DEBUG, "POPO  detected.\n");
					ndpi_int_popo_add_connection(ndpi_struct, flow);
					return;
				}
		}
	}

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_POPO);
}

#endif
