/*
 * filetopia.c
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
#ifdef NDPI_PROTOCOL_FILETOPIA


static void ndpi_int_filetopia_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FILETOPIA, NDPI_REAL_PROTOCOL);
}

void ndpi_search_filetopia_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (flow->l4.tcp.filetopia_stage == 0) {
		if (packet->payload_packet_len >= 50 && packet->payload_packet_len <= 70
			&& packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
			&& packet->payload[3] == 0x22 && packet->payload[packet->payload_packet_len - 1] == 0x2b) {
			NDPI_LOG(NDPI_PROTOCOL_FILETOPIA, ndpi_struct, NDPI_LOG_DEBUG, "Filetopia stage 1 detected\n");
			flow->l4.tcp.filetopia_stage = 1;
			return;
		}

	} else if (flow->l4.tcp.filetopia_stage == 1) {
		if (packet->payload_packet_len >= 100 && packet->payload[0] == 0x03
			&& packet->payload[1] == 0x9a && (packet->payload[3] == 0x22 || packet->payload[3] == 0x23)) {

			int i;
			for (i = 0; i < 10; i++) {	// check 10 bytes for valid ASCII printable characters
				if (!(packet->payload[5 + i] >= 0x20 && packet->payload[5 + i] <= 0x7e)) {
					goto end_filetopia_nothing_found;
				}
			}

			NDPI_LOG(NDPI_PROTOCOL_FILETOPIA, ndpi_struct, NDPI_LOG_DEBUG, "Filetopia stage 2 detected\n");
			flow->l4.tcp.filetopia_stage = 2;
			return;
		}


	} else if (flow->l4.tcp.filetopia_stage == 2) {
		if (packet->payload_packet_len >= 4 && packet->payload_packet_len <= 100
			&& packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
			&& (packet->payload[3] == 0x22 || packet->payload[3] == 0x23)) {
			NDPI_LOG(NDPI_PROTOCOL_FILETOPIA, ndpi_struct, NDPI_LOG_DEBUG, "Filetopia detected\n");
			ndpi_int_filetopia_add_connection(ndpi_struct, flow);
			return;
		}

	}

  end_filetopia_nothing_found:
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FILETOPIA);
}

#endif
