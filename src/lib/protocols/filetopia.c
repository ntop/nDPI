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

#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_FILETOPIA

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FILETOPIA

#include "ndpi_api.h"


static void ndpi_int_filetopia_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_FILETOPIA, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_filetopia_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG_DBG(ndpi_struct, "search Filetopia\n");

	if (flow->l4.tcp.filetopia_stage == 0) {
		if (packet->payload_packet_len >= 50 && packet->payload_packet_len <= 70
			&& packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
			&& packet->payload[3] == 0x22 && packet->payload[packet->payload_packet_len - 1] == 0x2b) {
			NDPI_LOG_DBG2(ndpi_struct, "Filetopia stage 1 detected\n");
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

			NDPI_LOG_DBG2(ndpi_struct, "Filetopia stage 2 detected\n");
			flow->l4.tcp.filetopia_stage = 2;
			return;
		}


	} else if (flow->l4.tcp.filetopia_stage == 2) {
		if (packet->payload_packet_len >= 4 && packet->payload_packet_len <= 100
			&& packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
			&& (packet->payload[3] == 0x22 || packet->payload[3] == 0x23)) {
			NDPI_LOG_INFO(ndpi_struct, "found Filetopia\n");
			ndpi_int_filetopia_add_connection(ndpi_struct, flow);
			return;
		}

	}

  end_filetopia_nothing_found:
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_filetopia_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Filetopia", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_FILETOPIA,
				      ndpi_search_filetopia_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

#endif
