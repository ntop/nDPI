/*
 * usenet.c
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

#ifdef NDPI_PROTOCOL_USENET


static void ndpi_int_usenet_add_connection(struct ndpi_detection_module_struct
											 *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_USENET, NDPI_REAL_PROTOCOL);
}



void ndpi_search_usenet_tcp(struct ndpi_detection_module_struct
							  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	NDPI_LOG(NDPI_PROTOCOL_USENET, ndpi_struct, NDPI_LOG_DEBUG, "USENET: search usenet.\n");





	NDPI_LOG(NDPI_PROTOCOL_USENET, ndpi_struct, NDPI_LOG_DEBUG, "USENET: STAGE IS %u.\n", flow->l4.tcp.usenet_stage);


	// check for the first server replay
	/*
	   200    Service available, posting allowed
	   201    Service available, posting prohibited
	 */
	if (flow->l4.tcp.usenet_stage == 0 && packet->payload_packet_len > 10
		&& ((memcmp(packet->payload, "200 ", 4) == 0)
			|| (memcmp(packet->payload, "201 ", 4) == 0))) {

		NDPI_LOG(NDPI_PROTOCOL_USENET, ndpi_struct, NDPI_LOG_DEBUG, "USENET: found 200 or 201.\n");
		flow->l4.tcp.usenet_stage = 1 + packet->packet_direction;

		NDPI_LOG(NDPI_PROTOCOL_USENET, ndpi_struct, NDPI_LOG_DEBUG, "USENET: maybe hit.\n");
		return;
	}

	/*
	   [C] AUTHINFO USER fred
	   [S] 381 Enter passphrase
	   [C] AUTHINFO PASS flintstone
	   [S] 281 Authentication accepted
	 */
	// check for client username
	if (flow->l4.tcp.usenet_stage == 2 - packet->packet_direction) {
		if (packet->payload_packet_len > 20 && (memcmp(packet->payload, "AUTHINFO USER ", 14) == 0)) {
			NDPI_LOG(NDPI_PROTOCOL_USENET, ndpi_struct, NDPI_LOG_DEBUG, "USENET: username found\n");
			flow->l4.tcp.usenet_stage = 3 + packet->packet_direction;

			NDPI_LOG(NDPI_PROTOCOL_USENET, ndpi_struct, NDPI_LOG_DEBUG, "USENET: found usenet.\n");
			ndpi_int_usenet_add_connection(ndpi_struct, flow);
			return;
		} else if (packet->payload_packet_len == 13 && (memcmp(packet->payload, "MODE READER\r\n", 13) == 0)) {
			NDPI_LOG(NDPI_PROTOCOL_USENET, ndpi_struct, NDPI_LOG_DEBUG,
					"USENET: no login necessary but we are a client.\n");

			NDPI_LOG(NDPI_PROTOCOL_USENET, ndpi_struct, NDPI_LOG_DEBUG, "USENET: found usenet.\n");
			ndpi_int_usenet_add_connection(ndpi_struct, flow);
			return;
		}
	}



	NDPI_LOG(NDPI_PROTOCOL_USENET, ndpi_struct, NDPI_LOG_DEBUG, "USENET: exclude usenet.\n");

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_USENET);

}

#endif
