/*
 * fasttrack.c
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

#ifdef NDPI_PROTOCOL_FASTTRACK



static void ndpi_int_fasttrack_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FASTTRACK, NDPI_CORRELATED_PROTOCOL);
}


void ndpi_search_fasttrack_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (packet->payload_packet_len > 6 && ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {
		NDPI_LOG(NDPI_PROTOCOL_FASTTRACK, ndpi_struct, NDPI_LOG_TRACE, "detected 0d0a at the end of the packet.\n");

		if (memcmp(packet->payload, "GIVE ", 5) == 0 && packet->payload_packet_len >= 8) {
			u_int16_t i;
			for (i = 5; i < (packet->payload_packet_len - 2); i++) {
				// make shure that the argument to GIVE is numeric
				if (!(packet->payload[i] >= '0' && packet->payload[i] <= '9')) {
					goto exclude_fasttrack;
				}
			}

			NDPI_LOG(NDPI_PROTOCOL_FASTTRACK, ndpi_struct, NDPI_LOG_TRACE, "FASTTRACK GIVE DETECTED\n");
			ndpi_int_fasttrack_add_connection(ndpi_struct, flow);
			return;
		}

		if (packet->payload_packet_len > 50 && memcmp(packet->payload, "GET /", 5) == 0) {
			u_int8_t a = 0;
			NDPI_LOG(NDPI_PROTOCOL_FASTTRACK, ndpi_struct, NDPI_LOG_TRACE, "detected GET /. \n");
			ndpi_parse_packet_line_info(ndpi_struct, flow);
			for (a = 0; a < packet->parsed_lines; a++) {
				if ((packet->line[a].len > 17 && memcmp(packet->line[a].ptr, "X-Kazaa-Username: ", 18) == 0)
					|| (packet->line[a].len > 23 && memcmp(packet->line[a].ptr, "User-Agent: PeerEnabler/", 24) == 0)) {
					NDPI_LOG(NDPI_PROTOCOL_FASTTRACK, ndpi_struct, NDPI_LOG_TRACE,
							"detected X-Kazaa-Username: || User-Agent: PeerEnabler/\n");
					ndpi_int_fasttrack_add_connection(ndpi_struct, flow);
					return;
				}
			}
		}
	}

  exclude_fasttrack:
	NDPI_LOG(NDPI_PROTOCOL_FASTTRACK, ndpi_struct, NDPI_LOG_TRACE, "fasttrack/kazaa excluded.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FASTTRACK);
}
#endif
