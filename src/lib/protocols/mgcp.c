/*
 * mgcp.c
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

#ifdef NDPI_PROTOCOL_MGCP

static void ndpi_int_mgcp_add_connection(struct ndpi_detection_module_struct
										   *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MGCP, NDPI_REAL_PROTOCOL);
}


	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_search_mgcp_connection(struct ndpi_detection_module_struct
												 *ndpi_struct, struct ndpi_flow_struct *flow)
{

	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	/* information about MGCP taken from http://en.wikipedia.org/wiki/MGCP */

	u_int16_t pos = 4;

	if (packet->payload_packet_len < 8) {
		goto mgcp_excluded;
	}

	/* packet must end with 0x0d0a or with 0x0a */
	if (packet->payload[packet->payload_packet_len - 1] != 0x0a
		&& get_u_int16_t(packet->payload, packet->payload_packet_len - 2) != htons(0x0d0a)) {
		goto mgcp_excluded;
	}



	if (packet->payload[0] != 'A' && packet->payload[0] != 'C' && packet->payload[0] != 'D' &&
		packet->payload[0] != 'E' && packet->payload[0] != 'M' && packet->payload[0] != 'N' &&
		packet->payload[0] != 'R') {
		goto mgcp_excluded;
	}
	if (memcmp(packet->payload, "AUEP ", 5) != 0 && memcmp(packet->payload, "AUCX ", 5) != 0 &&
		memcmp(packet->payload, "CRCX ", 5) != 0 && memcmp(packet->payload, "DLCX ", 5) != 0 &&
		memcmp(packet->payload, "EPCF ", 5) != 0 && memcmp(packet->payload, "MDCX ", 5) != 0 &&
		memcmp(packet->payload, "NTFY ", 5) != 0 && memcmp(packet->payload, "RQNT ", 5) != 0 &&
		memcmp(packet->payload, "RSIP ", 5) != 0) {
		goto mgcp_excluded;
	}
	// now search for string "MGCP " in the rest of the message
	while ((pos + 5) < packet->payload_packet_len) {
		if (memcmp(&packet->payload[pos], "MGCP ", 5) == 0) {
			NDPI_LOG(NDPI_PROTOCOL_MGCP, ndpi_struct, NDPI_LOG_DEBUG, "MGCP match.\n");
			ndpi_int_mgcp_add_connection(ndpi_struct, flow);
			return;
		}
		pos++;
	}

  mgcp_excluded:
	NDPI_LOG(NDPI_PROTOCOL_MGCP, ndpi_struct, NDPI_LOG_DEBUG, "exclude MGCP.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MGCP);
}


void ndpi_search_mgcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

	ndpi_search_mgcp_connection(ndpi_struct, flow);

}
#endif
