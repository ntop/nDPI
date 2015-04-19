/*
 * telnet.c
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
#ifdef NDPI_PROTOCOL_TELNET



static void ndpi_int_telnet_add_connection(struct ndpi_detection_module_struct
											 *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TELNET, NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 u_int8_t search_iac(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	u_int16_t a;

	if (packet->payload_packet_len < 3) {
		return 0;
	}

	if (!(packet->payload[0] == 0xff
		  && packet->payload[1] > 0xf9 && packet->payload[1] != 0xff && packet->payload[2] < 0x28)) {
		return 0;
	}

	a = 3;

	while (a < packet->payload_packet_len - 2) {
		// commands start with a 0xff byte followed by a command byte >= 0xf0 and < 0xff
		// command bytes 0xfb to 0xfe are followed by an option byte <= 0x28
		if (!(packet->payload[a] != 0xff ||
			  (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xf0) && (packet->payload[a + 1] <= 0xfa)) ||
			  (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xfb) && (packet->payload[a + 1] != 0xff)
			   && (packet->payload[a + 2] <= 0x28)))) {
			return 0;
		}
		a++;
	}

	return 1;
}

/* this detection also works asymmetrically */
void ndpi_search_telnet_tcp(struct ndpi_detection_module_struct
							  *ndpi_struct, struct ndpi_flow_struct *flow)
{
//  struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	NDPI_LOG(NDPI_PROTOCOL_TELNET, ndpi_struct, NDPI_LOG_DEBUG, "search telnet.\n");

	if (search_iac(ndpi_struct, flow) == 1) {

		if (flow->l4.tcp.telnet_stage == 2) {
			NDPI_LOG(NDPI_PROTOCOL_TELNET, ndpi_struct, NDPI_LOG_DEBUG, "telnet identified.\n");
			ndpi_int_telnet_add_connection(ndpi_struct, flow);
			return;
		}
		flow->l4.tcp.telnet_stage++;
		NDPI_LOG(NDPI_PROTOCOL_TELNET, ndpi_struct, NDPI_LOG_DEBUG, "telnet stage %u.\n", flow->l4.tcp.telnet_stage);
		return;
	}

	if ((flow->packet_counter < 12 && flow->l4.tcp.telnet_stage > 0) || flow->packet_counter < 6) {
		return;
	} else {
		NDPI_LOG(NDPI_PROTOCOL_TELNET, ndpi_struct, NDPI_LOG_DEBUG, "telnet excluded.\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_TELNET);
	}
	return;
}

#endif
