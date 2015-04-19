/*
 * shoutcast.c
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

#ifdef NDPI_PROTOCOL_SHOUTCAST

static void ndpi_int_shoutcast_add_connection(struct ndpi_detection_module_struct
												*ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SHOUTCAST, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_shoutcast_tcp(struct ndpi_detection_module_struct
								 *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	

	NDPI_LOG(NDPI_PROTOCOL_SHOUTCAST, ndpi_struct, NDPI_LOG_DEBUG, "search shoutcast.\n");

	if (flow->packet_counter == 1) {
/* this case in paul_upload_oddcast_002.pcap */
		if (packet->payload_packet_len >= 6
			&& packet->payload_packet_len < 80 && memcmp(packet->payload, "123456", 6) == 0) {
			NDPI_LOG(NDPI_PROTOCOL_SHOUTCAST, ndpi_struct, NDPI_LOG_DEBUG, "Shoutcast stage 1, \"123456\".\n");
			return;
		}
		if (flow->packet_counter < 3
#ifdef NDPI_PROTOCOL_HTTP
			&& packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP
#endif
			) {
			NDPI_LOG(NDPI_PROTOCOL_SHOUTCAST, ndpi_struct, NDPI_LOG_DEBUG,
					"http detected, need next packet for shoutcast detection.\n");
			if (packet->payload_packet_len > 4
				&& get_u_int32_t(packet->payload, packet->payload_packet_len - 4) != htonl(0x0d0a0d0a)) {
				NDPI_LOG(NDPI_PROTOCOL_SHOUTCAST, ndpi_struct, NDPI_LOG_DEBUG, "segmented packet found.\n");
				flow->l4.tcp.shoutcast_stage = 1 + packet->packet_direction;
			}
			return;
		}


		/*  else
		   goto exclude_shoutcast; */

	}
	/* evtl. für asym detection noch User-Agent:Winamp dazunehmen. */
	if (packet->payload_packet_len > 11 && memcmp(packet->payload, "ICY 200 OK\x0d\x0a", 12) == 0) {
		NDPI_LOG(NDPI_PROTOCOL_SHOUTCAST, ndpi_struct, NDPI_LOG_DEBUG, "found shoutcast by ICY 200 OK.\n");
		ndpi_int_shoutcast_add_connection(ndpi_struct, flow);
		return;
	}
	if (flow->l4.tcp.shoutcast_stage == 1 + packet->packet_direction
		&& flow->packet_direction_counter[packet->packet_direction] < 5) {
		return;
	}

	if (flow->packet_counter == 2) {
		if (packet->payload_packet_len == 2 && memcmp(packet->payload, "\x0d\x0a", 2) == 0) {
			NDPI_LOG(NDPI_PROTOCOL_SHOUTCAST, ndpi_struct, NDPI_LOG_DEBUG, "Shoutcast stage 1 continuation.\n");
			return;
		} else if (packet->payload_packet_len > 3 && memcmp(&packet->payload[0], "OK2", 3) == 0) {
			NDPI_LOG(NDPI_PROTOCOL_SHOUTCAST, ndpi_struct, NDPI_LOG_DEBUG, "Shoutcast stage 2, OK2 found.\n");
			return;
		} else
			goto exclude_shoutcast;
	} else if (flow->packet_counter == 3 || flow->packet_counter == 4) {
		if (packet->payload_packet_len > 3 && memcmp(&packet->payload[0], "OK2", 3) == 0) {
			NDPI_LOG(NDPI_PROTOCOL_SHOUTCAST, ndpi_struct, NDPI_LOG_DEBUG, "Shoutcast stage 2, OK2 found.\n");
			return;
		} else if (packet->payload_packet_len > 4 && memcmp(&packet->payload[0], "icy-", 4) == 0) {
			NDPI_LOG(NDPI_PROTOCOL_SHOUTCAST, ndpi_struct, NDPI_LOG_DEBUG, "Shoutcast detected.\n");
			ndpi_int_shoutcast_add_connection(ndpi_struct, flow);
			return;
		} else
			goto exclude_shoutcast;
	}

  exclude_shoutcast:
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SHOUTCAST);
	NDPI_LOG(NDPI_PROTOCOL_SHOUTCAST, ndpi_struct, NDPI_LOG_DEBUG, "Shoutcast excluded.\n");
}
#endif
