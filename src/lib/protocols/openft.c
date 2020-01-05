/*
 * openft.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_OPENFT

#include "ndpi_api.h"

static void ndpi_int_openft_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENFT, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_openft_tcp(struct ndpi_detection_module_struct
							  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	if (packet->payload_packet_len > 5 && memcmp(packet->payload, "GET /", 5) == 0) {
		NDPI_LOG_DBG2(ndpi_struct, "HTTP packet detected\n");
		ndpi_parse_packet_line_info(ndpi_struct, flow);
		if (packet->parsed_lines >= 2
			&& packet->line[1].len > 13 && memcmp(packet->line[1].ptr, "X-OpenftAlias:", 14) == 0) {
			NDPI_LOG_INFO(ndpi_struct, "found OpenFT\n");
			ndpi_int_openft_add_connection(ndpi_struct, flow);
			return;
		}
	}

	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_openft_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("OpenFT", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_OPENFT,
				      ndpi_search_openft_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
