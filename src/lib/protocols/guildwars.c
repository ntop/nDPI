/*
 * guildwars.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_GUILDWARS

#include "ndpi_api.h"


static void ndpi_int_guildwars_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_GUILDWARS, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_guildwars_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG_DBG(ndpi_struct, "search guildwars\n");

	if (packet->payload_packet_len == 64 && get_u_int16_t(packet->payload, 1) == ntohs(0x050c)
		&& memcmp(&packet->payload[50], "@2&P", 4) == 0) {
		NDPI_LOG_INFO(ndpi_struct, "found GuildWars version 29.350\n");
		ndpi_int_guildwars_add_connection(ndpi_struct, flow);
		return;
	}
	if (packet->payload_packet_len == 16 && get_u_int16_t(packet->payload, 1) == ntohs(0x040c)
		&& get_u_int16_t(packet->payload, 4) == ntohs(0xa672)
		&& packet->payload[8] == 0x01 && packet->payload[12] == 0x04) {
		NDPI_LOG_INFO(ndpi_struct, "found GuildWars version 29.350\n");
		ndpi_int_guildwars_add_connection(ndpi_struct, flow);
		return;
	}
	if (packet->payload_packet_len == 21 && get_u_int16_t(packet->payload, 0) == ntohs(0x0100)
		&& get_u_int32_t(packet->payload, 5) == ntohl(0xf1001000)
		&& packet->payload[9] == 0x01) {
		NDPI_LOG_INFO(ndpi_struct, "found GuildWars version 216.107.245.50\n");
		ndpi_int_guildwars_add_connection(ndpi_struct, flow);
		return;
	}

	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_guildwars_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
    ndpi_set_bitmask_protocol_detection("Guildwars", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_GUILDWARS,
				      ndpi_search_guildwars_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

    *id += 1;
}
