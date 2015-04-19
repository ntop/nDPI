/*
 * winmx.c
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

#ifdef NDPI_PROTOCOL_WINMX


static void ndpi_int_winmx_add_connection(struct ndpi_detection_module_struct
											*ndpi_struct, struct ndpi_flow_struct *flow);

static void ndpi_int_winmx_add_connection(struct ndpi_detection_module_struct
											*ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_WINMX, NDPI_REAL_PROTOCOL);
}


void ndpi_search_winmx_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;


	if (flow->l4.tcp.winmx_stage == 0) {
		if (packet->payload_packet_len == 1 || (packet->payload_packet_len > 1 && packet->payload[0] == 0x31)) {
			return;
		}
		/* did not see this pattern in any trace that we have */
		if (((packet->payload_packet_len) == 4)
			&& (memcmp(packet->payload, "SEND", 4) == 0)) {

			NDPI_LOG(NDPI_PROTOCOL_WINMX, ndpi_struct, NDPI_LOG_DEBUG, "maybe WinMX Send\n");
			flow->l4.tcp.winmx_stage = 1;
			return;
		}

		if (((packet->payload_packet_len) == 3)
			&& (memcmp(packet->payload, "GET", 3) == 0)) {
			NDPI_LOG(NDPI_PROTOCOL_WINMX, ndpi_struct, NDPI_LOG_DEBUG, "found winmx by GET\n");
			ndpi_int_winmx_add_connection(ndpi_struct, flow);
			return;
		}


		if (packet->payload_packet_len == 149 && packet->payload[0] == '8') {
			NDPI_LOG(NDPI_PROTOCOL_WINMX, ndpi_struct, NDPI_LOG_DEBUG, "maybe WinMX\n");
			if (get_u_int32_t(packet->payload, 17) == 0
				&& get_u_int32_t(packet->payload, 21) == 0
				&& get_u_int32_t(packet->payload, 25) == 0
				&& get_u_int16_t(packet->payload, 39) == 0 && get_u_int16_t(packet->payload, 135) == htons(0x7edf)
				&& get_u_int16_t(packet->payload, 147) == htons(0xf792)) {

				NDPI_LOG(NDPI_PROTOCOL_WINMX, ndpi_struct, NDPI_LOG_DEBUG,
						"found winmx by pattern in first packet\n");
				ndpi_int_winmx_add_connection(ndpi_struct, flow);
				return;
			}
		}
		/* did not see this pattern in any trace that we have */
	} else if (flow->l4.tcp.winmx_stage == 1) {
		if (packet->payload_packet_len > 10 && packet->payload_packet_len < 1000) {
			u_int16_t left = packet->payload_packet_len - 1;
			while (left > 0) {
				if (packet->payload[left] == ' ') {
					NDPI_LOG(NDPI_PROTOCOL_WINMX, ndpi_struct, NDPI_LOG_DEBUG, "found winmx in second packet\n");
					ndpi_int_winmx_add_connection(ndpi_struct, flow);
					return;
				} else if (packet->payload[left] < '0' || packet->payload[left] > '9') {
					break;
				}
				left--;
			}
		}
	}

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_WINMX);
}

#endif
