/*
 * usenet.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_USENET

#include "ndpi_api.h"

static void ndpi_int_usenet_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_USENET, NDPI_PROTOCOL_UNKNOWN);
}



void ndpi_search_usenet_tcp(struct ndpi_detection_module_struct
							  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG_DBG(ndpi_struct, "search usenet\n");

	NDPI_LOG_DBG2(ndpi_struct, "STAGE IS %u\n", flow->l4.tcp.usenet_stage);

	// check for the first server replay
	/*
	   200    Service available, posting allowed
	   201    Service available, posting prohibited
	 */
	if (flow->l4.tcp.usenet_stage == 0 && packet->payload_packet_len > 10
		&& ((memcmp(packet->payload, "200 ", 4) == 0)
			|| (memcmp(packet->payload, "201 ", 4) == 0))) {

		NDPI_LOG_DBG2(ndpi_struct, "found 200 or 201\n");
		flow->l4.tcp.usenet_stage = 1 + packet->packet_direction;

		NDPI_LOG_DBG2(ndpi_struct, "maybe hit\n");
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
			NDPI_LOG_DBG2(ndpi_struct, "username found\n");
			flow->l4.tcp.usenet_stage = 3 + packet->packet_direction;

			NDPI_LOG_INFO(ndpi_struct, "found usenet\n");
			ndpi_int_usenet_add_connection(ndpi_struct, flow);
			return;
		} else if (packet->payload_packet_len == 13 && (memcmp(packet->payload, "MODE READER\r\n", 13) == 0)) {
			NDPI_LOG_DBG2(ndpi_struct,
					"no login necessary but we are a client.\n");

			NDPI_LOG_INFO(ndpi_struct, "found usenet\n");
			ndpi_int_usenet_add_connection(ndpi_struct, flow);
			return;
		}
	}

	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_usenet_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Usenet", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_USENET,
				      ndpi_search_usenet_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
