/*
 * pcanywhere.c
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
#ifdef NDPI_PROTOCOL_PCANYWHERE

static void ndpi_int_pcanywhere_add_connection(struct ndpi_detection_module_struct
												 *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_PCANYWHERE, NDPI_REAL_PROTOCOL);
}

void ndpi_search_pcanywhere(struct ndpi_detection_module_struct
							  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (packet->udp != NULL && packet->udp->dest == htons(5632)
		&& packet->payload_packet_len == 2
		&& (memcmp(packet->payload, "NQ", 2) == 0 || memcmp(packet->payload, "ST", 2) == 0)) {
		NDPI_LOG(NDPI_PROTOCOL_PCANYWHERE, ndpi_struct, NDPI_LOG_DEBUG,
				"PC Anywhere name or status query detected.\n");
		ndpi_int_pcanywhere_add_connection(ndpi_struct, flow);
		return;
	}

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_PCANYWHERE);
}

#endif
