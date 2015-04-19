/*
 * ssdp.c
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
#ifdef NDPI_PROTOCOL_SSDP


static void ndpi_int_ssdp_add_connection(struct ndpi_detection_module_struct
										   *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SSDP, NDPI_REAL_PROTOCOL);
}

/* this detection also works asymmetrically */
void ndpi_search_ssdp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	NDPI_LOG(NDPI_PROTOCOL_SSDP, ndpi_struct, NDPI_LOG_DEBUG, "search ssdp.\n");
	if (packet->udp != NULL) {

		if (packet->payload_packet_len > 100) {
			if ((memcmp(packet->payload, "M-SEARCH * HTTP/1.1", 19) == 0)
				|| memcmp(packet->payload, "NOTIFY * HTTP/1.1", 17) == 0) {


				NDPI_LOG(NDPI_PROTOCOL_SSDP, ndpi_struct, NDPI_LOG_DEBUG, "found ssdp.\n");
				ndpi_int_ssdp_add_connection(ndpi_struct, flow);
				return;
			}

#define SSDP_HTTP "HTTP/1.1 200 OK\r\n"
			if(memcmp(packet->payload, SSDP_HTTP, strlen(SSDP_HTTP)) == 0) {
			  NDPI_LOG(NDPI_PROTOCOL_SSDP, ndpi_struct, NDPI_LOG_DEBUG, "found ssdp.\n");
			  ndpi_int_ssdp_add_connection(ndpi_struct, flow);
			  return;
			}
		}
	}

	NDPI_LOG(NDPI_PROTOCOL_SSDP, ndpi_struct, NDPI_LOG_DEBUG, "ssdp excluded.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SSDP);
}

#endif
