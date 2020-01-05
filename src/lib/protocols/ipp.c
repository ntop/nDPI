/*
 * ipp.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_IPP

#include "ndpi_api.h"


static void ndpi_int_ipp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow/* , ndpi_protocol_type_t protocol_type */)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_IPP, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_ipp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;	
	u_int8_t i;

	NDPI_LOG_DBG(ndpi_struct, "search ipp\n");

	if (packet->payload_packet_len > 20) {

		NDPI_LOG_DBG2(ndpi_struct,
				"searching for a payload with a pattern like 'number(1to8)blanknumber(1to3)ipp://.\n");
		/* this pattern means that there is a printer saying that his state is idle,
		 * means that he is not printing anything at the moment */
		i = 0;

		if (packet->payload[i] < '0' || packet->payload[i] > '9') {
			NDPI_LOG_DBG2(ndpi_struct, "payload does not begin with a number\n");
			goto search_for_next_pattern;
		}

		for (;;) {
			i++;
			if (!((packet->payload[i] >= '0' && packet->payload[i] <= '9') ||
				  (packet->payload[i] >= 'a' && packet->payload[i] <= 'f') ||
				  (packet->payload[i] >= 'A' && packet->payload[i] <= 'F')) || i > 8) {
				NDPI_LOG_DBG2(ndpi_struct,
						"read symbols while the symbol is a number.\n");
				break;
			}
		}

		if (packet->payload[i++] != ' ') {
			NDPI_LOG_DBG2(ndpi_struct, "there is no blank following the number\n");
			goto search_for_next_pattern;
		}

		if (packet->payload[i] < '0' || packet->payload[i] > '9') {
			NDPI_LOG_DBG2(ndpi_struct, "no number following the blank\n");
			goto search_for_next_pattern;
		}

		for (;;) {
			i++;
			if (packet->payload[i] < '0' || packet->payload[i] > '9' || i > 12) {
				NDPI_LOG_DBG2(ndpi_struct,
						"read symbols while the symbol is a number.\n");
				break;
			}
		}

		if (memcmp(&packet->payload[i], " ipp://", 7) != 0) {
			NDPI_LOG_DBG2(ndpi_struct, "the string ' ipp://' does not follow\n");
			goto search_for_next_pattern;
		}

		NDPI_LOG_INFO(ndpi_struct, "found ipp\n");
		ndpi_int_ipp_add_connection(ndpi_struct, flow);
		return;
	}

  search_for_next_pattern:

	if (packet->payload_packet_len > 3 && memcmp(packet->payload, "POST", 4) == 0) {
		ndpi_parse_packet_line_info(ndpi_struct, flow);
		if (packet->content_line.ptr != NULL && packet->content_line.len > 14
			&& memcmp(packet->content_line.ptr, "application/ipp", 15) == 0) {
			NDPI_LOG_INFO(ndpi_struct, "found ipp via POST ... application/ipp\n");
			ndpi_int_ipp_add_connection(ndpi_struct, flow);
			return;
		}
	}
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_ipp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("IPP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IPP,
				      ndpi_search_ipp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
