/*
 * bgp.c
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
#ifdef NDPI_PROTOCOL_BGP


static void ndpi_int_bgp_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_BGP, NDPI_REAL_PROTOCOL);
}

/* this detection also works asymmetrically */
void ndpi_search_bgp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (packet->payload_packet_len > 18 &&
		get_u_int64_t(packet->payload, 0) == 0xffffffffffffffffULL &&
		get_u_int64_t(packet->payload, 8) == 0xffffffffffffffffULL &&
		ntohs(get_u_int16_t(packet->payload, 16)) <= packet->payload_packet_len &&
		(packet->tcp->dest == htons(179) || packet->tcp->source == htons(179))
		&& packet->payload[18] < 5) {
		NDPI_LOG(NDPI_PROTOCOL_BGP, ndpi_struct, NDPI_LOG_DEBUG, "BGP detected.\n");
		ndpi_int_bgp_add_connection(ndpi_struct, flow);
		return;
	}

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_BGP);
}

#endif
