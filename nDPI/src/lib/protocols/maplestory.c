/*
 * maplestory.c
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

#ifdef NDPI_PROTOCOL_MAPLESTORY

static void ndpi_int_maplestory_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MAPLESTORY, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_maplestory(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;



	if (packet->payload_packet_len == 16
		&& (ntohl(get_u_int32_t(packet->payload, 0)) == 0x0e003a00 || ntohl(get_u_int32_t(packet->payload, 0)) == 0x0e003b00
			|| ntohl(get_u_int32_t(packet->payload, 0)) == 0x0e004200)
		&& ntohs(get_u_int16_t(packet->payload, 4)) == 0x0100 && (packet->payload[6] == 0x32 || packet->payload[6] == 0x33)) {
		NDPI_LOG(NDPI_PROTOCOL_MAPLESTORY, ndpi_struct, NDPI_LOG_DEBUG, "found maplestory.\n");
		ndpi_int_maplestory_add_connection(ndpi_struct, flow);
		return;
	}

	if (packet->payload_packet_len > NDPI_STATICSTRING_LEN("GET /maple")
		&& memcmp(packet->payload, "GET /maple", NDPI_STATICSTRING_LEN("GET /maple")) == 0) {
		ndpi_parse_packet_line_info(ndpi_struct, flow);
		/* Maplestory update */
		if (packet->payload_packet_len > NDPI_STATICSTRING_LEN("GET /maple/patch")
			&& packet->payload[NDPI_STATICSTRING_LEN("GET /maple")] == '/') {
			if (packet->user_agent_line.ptr != NULL && packet->host_line.ptr != NULL
				&& packet->user_agent_line.len == NDPI_STATICSTRING_LEN("Patcher")
				&& packet->host_line.len > NDPI_STATICSTRING_LEN("patch.")
				&& memcmp(&packet->payload[NDPI_STATICSTRING_LEN("GET /maple/")], "patch",
						  NDPI_STATICSTRING_LEN("patch")) == 0
				&& memcmp(packet->user_agent_line.ptr, "Patcher", NDPI_STATICSTRING_LEN("Patcher")) == 0
				&& memcmp(packet->host_line.ptr, "patch.", NDPI_STATICSTRING_LEN("patch.")) == 0) {
				NDPI_LOG(NDPI_PROTOCOL_MAPLESTORY, ndpi_struct, NDPI_LOG_DEBUG, "found maplestory update.\n");
				ndpi_int_maplestory_add_connection(ndpi_struct, flow);
				return;
			}
		} else if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len == NDPI_STATICSTRING_LEN("AspINet")
				   && memcmp(&packet->payload[NDPI_STATICSTRING_LEN("GET /maple")], "story/",
							 NDPI_STATICSTRING_LEN("story/")) == 0
				   && memcmp(packet->user_agent_line.ptr, "AspINet", NDPI_STATICSTRING_LEN("AspINet")) == 0) {
			NDPI_LOG(NDPI_PROTOCOL_MAPLESTORY, ndpi_struct, NDPI_LOG_DEBUG, "found maplestory update.\n");
			ndpi_int_maplestory_add_connection(ndpi_struct, flow);
			return;
		}
	}

	NDPI_LOG(NDPI_PROTOCOL_MAPLESTORY, ndpi_struct, NDPI_LOG_DEBUG, "exclude maplestory.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MAPLESTORY);

}


void init_maplestory_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("MapleStory", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MAPLESTORY,
				      ndpi_search_maplestory,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
