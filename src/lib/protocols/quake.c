/*
 * quake.c
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

#ifdef NDPI_PROTOCOL_QUAKE

static void ndpi_int_quake_add_connection(struct ndpi_detection_module_struct
											*ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUAKE, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_quake(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if ((packet->payload_packet_len == 14
		 && get_u_int16_t(packet->payload, 0) == 0xffff && memcmp(&packet->payload[2], "getInfo", 7) == 0)
		|| (packet->payload_packet_len == 17
			&& get_u_int16_t(packet->payload, 0) == 0xffff && memcmp(&packet->payload[2], "challenge", 9) == 0)
		|| (packet->payload_packet_len > 20
			&& packet->payload_packet_len < 30
			&& get_u_int16_t(packet->payload, 0) == 0xffff && memcmp(&packet->payload[2], "getServers", 10) == 0)) {
		NDPI_LOG(NDPI_PROTOCOL_QUAKE, ndpi_struct, NDPI_LOG_DEBUG, "Quake IV detected.\n");
		ndpi_int_quake_add_connection(ndpi_struct, flow);
		return;
	}

	/* Quake III/Quake Live */
	if (packet->payload_packet_len == 15 && get_u_int32_t(packet->payload, 0) == 0xffffffff
		&& memcmp(&packet->payload[4], "getinfo", NDPI_STATICSTRING_LEN("getinfo")) == 0) {
		NDPI_LOG(NDPI_PROTOCOL_QUAKE, ndpi_struct, NDPI_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
		ndpi_int_quake_add_connection(ndpi_struct, flow);
		return;
	}
	if (packet->payload_packet_len == 16 && get_u_int32_t(packet->payload, 0) == 0xffffffff
		&& memcmp(&packet->payload[4], "getchallenge", NDPI_STATICSTRING_LEN("getchallenge")) == 0) {
		NDPI_LOG(NDPI_PROTOCOL_QUAKE, ndpi_struct, NDPI_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
		ndpi_int_quake_add_connection(ndpi_struct, flow);
		return;
	}
	if (packet->payload_packet_len > 20 && packet->payload_packet_len < 30
		&& get_u_int32_t(packet->payload, 0) == 0xffffffff
		&& memcmp(&packet->payload[4], "getservers", NDPI_STATICSTRING_LEN("getservers")) == 0) {
		NDPI_LOG(NDPI_PROTOCOL_QUAKE, ndpi_struct, NDPI_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
		ndpi_int_quake_add_connection(ndpi_struct, flow);
		return;
	}



	/* ports for startup packet:
	   Quake I        26000 (starts with 0x8000)
	   Quake II       27910
	   Quake III      27960 (increases with each player)
	   Quake IV       27650
	   Quake World    27500
	   Quake Wars     ?????
	 */

	NDPI_LOG(NDPI_PROTOCOL_QUAKE, ndpi_struct, NDPI_LOG_DEBUG, "Quake excluded.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUAKE);
}


void init_quake_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Quake", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_QUAKE,
				      ndpi_search_quake,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
