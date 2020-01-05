/*
 * pptp.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_PPTP

#include "ndpi_api.h"

static void ndpi_int_pptp_add_connection(struct ndpi_detection_module_struct
										   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PPTP, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_pptp(struct ndpi_detection_module_struct
						*ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG_DBG(ndpi_struct, "search pptp\n");

	if (packet->payload_packet_len >= 10 && get_u_int16_t(packet->payload, 0) == htons(packet->payload_packet_len)
		&& get_u_int16_t(packet->payload, 2) == htons(0x0001)	/* message type: control message */
		&&get_u_int32_t(packet->payload, 4) == htonl(0x1a2b3c4d)	/* cookie: correct */
		&&(get_u_int16_t(packet->payload, 8) == htons(0x0001)	/* control type: start-control-connection-request */
		)) {

		NDPI_LOG_INFO(ndpi_struct, "found pptp\n");
		ndpi_int_pptp_add_connection(ndpi_struct, flow);
		return;
	}

	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_pptp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("PPTP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_PPTP,
				      ndpi_search_pptp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
