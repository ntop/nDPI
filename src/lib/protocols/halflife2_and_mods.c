/*
 * halflife2_and_mods.c
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
#ifdef NDPI_PROTOCOL_HALFLIFE2


static void ndpi_int_halflife2_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HALFLIFE2, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_halflife2(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (flow->l4.udp.halflife2_stage == 0) {
		if (packet->payload_packet_len >= 20
			&& get_u_int32_t(packet->payload, 0) == 0xFFFFFFFF
			&& get_u_int32_t(packet->payload, packet->payload_packet_len - 4) == htonl(0x30303000)) {
			flow->l4.udp.halflife2_stage = 1 + packet->packet_direction;
			NDPI_LOG(NDPI_PROTOCOL_HALFLIFE2, ndpi_struct, NDPI_LOG_DEBUG,
					"halflife2 client req detected, waiting for server reply\n");
			return;
		}
	} else if (flow->l4.udp.halflife2_stage == 2 - packet->packet_direction) {
		if (packet->payload_packet_len >= 20
			&& get_u_int32_t(packet->payload, 0) == 0xFFFFFFFF
			&& get_u_int32_t(packet->payload, packet->payload_packet_len - 4) == htonl(0x30303000)) {
			ndpi_int_halflife2_add_connection(ndpi_struct, flow);
			NDPI_LOG(NDPI_PROTOCOL_HALFLIFE2, ndpi_struct, NDPI_LOG_DEBUG, "halflife2 server reply detected\n");
			return;
		}
	}


	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HALFLIFE2);
}


void init_halflife2_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("HalfLife2", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_HALFLIFE2,
				      ndpi_search_halflife2,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
