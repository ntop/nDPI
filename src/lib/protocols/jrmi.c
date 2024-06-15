/*
 * jrmi.c
 *
 * Copyright (C) 2024 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_JRMI

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_jrmi_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow) {
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JRMI, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_jrmi(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
			     
	struct ndpi_packet_struct *packet = &ndpi_struct->packet;

	NDPI_LOG_DBG(ndpi_struct, "search jrmi\n");

	//>5 because of the version
	if(packet->payload_packet_len > 5) {
		if(packet->payload[0] == 0x4a &&
			packet->payload[1] == 0x52 &&
			packet->payload[2] == 0x4d &&
			packet->payload[3] == 0x49 ) {
			NDPI_LOG_INFO(ndpi_struct, "found jrmi over tcp\n");
			ndpi_int_jrmi_add_connection(ndpi_struct, flow);
			return;
		}
	}
	
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_jrmi_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id) {
	ndpi_set_bitmask_protocol_detection("JRMI", ndpi_struct, *id,
					    NDPI_PROTOCOL_JRMI,
					    ndpi_search_jrmi,
					    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
					    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
					    ADD_TO_DETECTION_BITMASK);

	*id += 1;
}

