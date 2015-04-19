/*
 * veohtv.c
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


#ifdef NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV

static void ndpi_int_veohtv_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					   struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV, protocol_type);
}

void ndpi_search_veohtv_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV)
		return;

	if (flow->l4.tcp.veoh_tv_stage == 1 || flow->l4.tcp.veoh_tv_stage == 2) {
		if (packet->packet_direction != flow->setup_packet_direction &&
			packet->payload_packet_len > NDPI_STATICSTRING_LEN("HTTP/1.1 20")
			&& memcmp(packet->payload, "HTTP/1.1 ", NDPI_STATICSTRING_LEN("HTTP/1.1 ")) == 0 &&
			(packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '2' ||
			 packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '3' ||
			 packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '4' ||
			 packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '5')) {
#ifdef NDPI_CONTENT_FLASH
			ndpi_parse_packet_line_info(ndpi_struct, flow);
			if (packet->detected_protocol_stack[0] == NDPI_CONTENT_FLASH &&
				packet->server_line.ptr != NULL &&
				packet->server_line.len > NDPI_STATICSTRING_LEN("Veoh-") &&
				memcmp(packet->server_line.ptr, "Veoh-", NDPI_STATICSTRING_LEN("Veoh-")) == 0) {
				NDPI_LOG(NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV, ndpi_struct, NDPI_LOG_DEBUG, "VeohTV detected.\n");
				ndpi_int_veohtv_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				return;
			}
#endif
			if (flow->l4.tcp.veoh_tv_stage == 2) {
				NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask,
											   NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV);
				return;
			}
			NDPI_LOG(NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV, ndpi_struct, NDPI_LOG_DEBUG, "VeohTV detected.\n");
			ndpi_int_veohtv_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			return;
		} else if (flow->packet_direction_counter[(flow->setup_packet_direction == 1) ? 0 : 1] > 3) {
			if (flow->l4.tcp.veoh_tv_stage == 2) {
				NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask,
											   NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV);
				return;
			}
			NDPI_LOG(NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV, ndpi_struct, NDPI_LOG_DEBUG, "VeohTV detected.\n");
			ndpi_int_veohtv_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
			return;
		} else {
			if (flow->packet_counter > 10) {
				if (flow->l4.tcp.veoh_tv_stage == 2) {
					NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask,
												   NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV);
					return;
				}
				NDPI_LOG(NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV, ndpi_struct, NDPI_LOG_DEBUG, "VeohTV detected.\n");
				ndpi_int_veohtv_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				return;
			}
			return;
		}
	} else if (packet->udp) {
		/* UDP packets from Veoh Client Player
		 *
		 * packet starts with 16 byte random? value
		 * then a 4 byte mode value
		 *   values between 21 and 26 has been seen 
		 * then a 4 byte counter */

		if (packet->payload_packet_len == 28 &&
			get_u_int32_t(packet->payload, 16) == htonl(0x00000021) &&
			get_u_int32_t(packet->payload, 20) == htonl(0x00000000) && get_u_int32_t(packet->payload, 24) == htonl(0x01040000)) {
			NDPI_LOG(NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV, ndpi_struct, NDPI_LOG_DEBUG, "UDP VeohTV found.\n");
			ndpi_int_veohtv_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}
	}


	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV);
}
#endif
