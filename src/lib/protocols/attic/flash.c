/*
 * flash.c
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


#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_FLASH

static void ndpi_int_flash_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_FLASH);
}

void ndpi_search_flash(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (flow->l4.tcp.flash_stage == 0 && packet->payload_packet_len > 0
		&& (packet->payload[0] == 0x03 || packet->payload[0] == 0x06)) {
		flow->l4.tcp.flash_bytes = packet->payload_packet_len;
		if (packet->tcp->psh == 0) {
			NDPI_LOG(NDPI_PROTOCOL_FLASH, ndpi_struct, NDPI_LOG_DEBUG, "FLASH pass 1: \n");
			flow->l4.tcp.flash_stage = packet->packet_direction + 1;

			NDPI_LOG(NDPI_PROTOCOL_FLASH, ndpi_struct, NDPI_LOG_DEBUG,
					"FLASH pass 1: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
					flow->l4.tcp.flash_bytes);
			return;
		} else if (packet->tcp->psh != 0 && flow->l4.tcp.flash_bytes == 1537) {
			NDPI_LOG(NDPI_PROTOCOL_FLASH, ndpi_struct, NDPI_LOG_DEBUG,
					"FLASH hit: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
					flow->l4.tcp.flash_bytes);
			flow->l4.tcp.flash_stage = 3;
			ndpi_int_flash_add_connection(ndpi_struct, flow);
			return;
		}
	} else if (flow->l4.tcp.flash_stage == 1 + packet->packet_direction) {
		flow->l4.tcp.flash_bytes += packet->payload_packet_len;
		if (packet->tcp->psh != 0 && flow->l4.tcp.flash_bytes == 1537) {
			NDPI_LOG(NDPI_PROTOCOL_FLASH, ndpi_struct, NDPI_LOG_DEBUG,
					"FLASH hit: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
					flow->l4.tcp.flash_bytes);
			flow->l4.tcp.flash_stage = 3;
			ndpi_int_flash_add_connection(ndpi_struct, flow);
			return;
		} else if (packet->tcp->psh == 0 && flow->l4.tcp.flash_bytes < 1537) {
			NDPI_LOG(NDPI_PROTOCOL_FLASH, ndpi_struct, NDPI_LOG_DEBUG,
					"FLASH pass 2: flash_stage: %u, flash_bytes: %u\n", flow->l4.tcp.flash_stage,
					flow->l4.tcp.flash_bytes);
			return;
		}
	}

	NDPI_LOG(NDPI_PROTOCOL_FLASH, ndpi_struct, NDPI_LOG_DEBUG,
			"FLASH might be excluded: flash_stage: %u, flash_bytes: %u, packet_direction: %u\n",
			flow->l4.tcp.flash_stage, flow->l4.tcp.flash_bytes, packet->packet_direction);

#ifdef NDPI_PROTOCOL_HTTP
	if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HTTP) != 0) {
#endif							/* NDPI_PROTOCOL_HTTP */
		NDPI_LOG(NDPI_PROTOCOL_FLASH, ndpi_struct, NDPI_LOG_DEBUG, "FLASH: exclude\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FLASH);
#ifdef NDPI_PROTOCOL_HTTP
	} else {
		NDPI_LOG(NDPI_PROTOCOL_FLASH, ndpi_struct, NDPI_LOG_DEBUG, "FLASH avoid early exclude from http\n");
	}
#endif							/* NDPI_PROTOCOL_HTTP */

}
#endif
