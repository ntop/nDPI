/*
 * amqp.c
 *
 * Copyright (C) 2011-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_AMQP

#include "ndpi_api.h"


PACK_ON
struct amqp_header {
	u_int8_t ptype;
	u_int16_t channel;
	u_int32_t length;
	u_int16_t class_id, method;
} PACK_OFF;

static void ndpi_int_amqp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow/* , */
					 /* ndpi_protocol_type_t protocol_type */) {
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_AMQP, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_amqp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG_DBG(ndpi_struct, "search amqp\n");

	if (packet->tcp != NULL) {
		if(packet->payload_packet_len > sizeof(struct amqp_header)) {
			struct amqp_header *h = (struct amqp_header*)packet->payload;

			if(h->ptype <= 3) {
				u_int32_t length = htonl(h->length);

				if(((length+8) >= packet->payload_packet_len)
				   && (length < 32768) /* Upper bound */) {					
					u_int16_t class_id = htons(h->class_id);
				
					if((class_id >= 10) /* Connection */
					   && (class_id <= 110) /* Tunnel */) {
						u_int16_t method = htons(h->method);

						if(method <= 120 /* Method basic NACK */) {
							NDPI_LOG_INFO(ndpi_struct, "found amqp over tcp\n");
							ndpi_int_amqp_add_connection(ndpi_struct, flow);
							return;
						}
					}
				}
			}
		}
	} else {
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	}
}


void init_amqp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
	ndpi_set_bitmask_protocol_detection("AMQP", ndpi_struct, detection_bitmask, *id,
					    NDPI_PROTOCOL_AMQP,
					    ndpi_search_amqp,
					    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
					    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
					    ADD_TO_DETECTION_BITMASK);

	*id += 1;
}

