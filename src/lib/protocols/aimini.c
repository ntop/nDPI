/*
 * aimini.c
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

#ifdef NDPI_PROTOCOL_AIMINI


static void ndpi_int_aimini_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, 
					   ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_AIMINI, protocol_type);
}


static u_int8_t is_special_aimini_host(struct ndpi_int_one_line_struct host_line)
{
	if (host_line.ptr != NULL && host_line.len >= NDPI_STATICSTRING_LEN("X.X.X.X.aimini.net")) {
		if ((get_u_int32_t(host_line.ptr, 0) & htonl(0x00ff00ff)) == htonl(0x002e002e) &&
			(get_u_int32_t(host_line.ptr, 4) & htonl(0x00ff00ff)) == htonl(0x002e002e) &&
			memcmp(&host_line.ptr[8], "aimini.net", NDPI_STATICSTRING_LEN("aimini.net")) == 0) {
			return 1;
		}
	}
	return 0;
}

void ndpi_search_aimini(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	//    struct ndpi_id_struct         *src=ndpi_struct->src;
	//    struct ndpi_id_struct         *dst=ndpi_struct->dst;


	NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "search aimini.\n");

	if (packet->udp != NULL) {
		if (flow->l4.udp.aimini_stage == 0) {
			if (packet->payload_packet_len == 64 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x010b) {
				flow->l4.udp.aimini_stage = 1;
				NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 1.\n");
				return;
			}
			if (packet->payload_packet_len == 136
				&& (ntohs(get_u_int16_t(packet->payload, 0)) == 0x01c9 || ntohs(get_u_int16_t(packet->payload, 0)) == 0x0165)) {
				flow->l4.udp.aimini_stage = 4;
				NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 4.\n");
				return;
			}
			if (packet->payload_packet_len == 88 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x0101) {
				flow->l4.udp.aimini_stage = 7;
				NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 7.\n");
				return;
			}
			if (packet->payload_packet_len == 104 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x0102) {
				flow->l4.udp.aimini_stage = 10;
				NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 10.\n");
				return;
			}
			if (packet->payload_packet_len == 32 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x01ca) {
				flow->l4.udp.aimini_stage = 13;
				NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 13.\n");
				return;
			}
			if (packet->payload_packet_len == 16 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x010c) {
				flow->l4.udp.aimini_stage = 16;
				NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 16.\n");
				return;
			}
		}
		/* first packet chronology: (len, value): (64, 0x010b), (>100, 0x0115), (16, 0x010c || 64, 0x010b || 88, 0x0115),
		 * (16, 0x010c || 64, 0x010b || >100, 0x0115)
		 */
		if (flow->l4.udp.aimini_stage == 1 && packet->payload_packet_len > 100
			&& ntohs(get_u_int16_t(packet->payload, 0)) == 0x0115) {
			flow->l4.udp.aimini_stage = 2;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 2.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 2 &&
			((packet->payload_packet_len == 16 && get_u_int16_t(packet->payload, 0) == htons(0x010c)) ||
			 (packet->payload_packet_len == 64 && get_u_int16_t(packet->payload, 0) == htons(0x010b)) ||
			 (packet->payload_packet_len == 88 && get_u_int16_t(packet->payload, 0) == ntohs(0x0115)))) {
			flow->l4.udp.aimini_stage = 3;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 3.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 3
			&& ((packet->payload_packet_len == 16 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x010c)
				|| (packet->payload_packet_len == 64 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x010b)
				|| (packet->payload_packet_len > 100 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x0115))) {
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "found aimini (64, 0x010b), (>300, 0x0115), "
					"(16, 0x010c || 64, 0x010b), (16, 0x010c || 64, 0x010b || >100, 0x0115).\n");
			ndpi_int_aimini_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}

		/* second packet chronology: (len, value): (136, 0x01c9), (136, 0x01c9),(136, 0x01c9),(136, 0x01c9 || 32, 0x01ca) */

		if (flow->l4.udp.aimini_stage == 4 && packet->payload_packet_len == 136
			&& (ntohs(get_u_int16_t(packet->payload, 0)) == 0x01c9 || ntohs(get_u_int16_t(packet->payload, 0)) == 0x0165)) {
			flow->l4.udp.aimini_stage = 5;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 5.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 5 && (packet->payload_packet_len == 136
											   && (ntohs(get_u_int16_t(packet->payload, 0)) == 0x01c9
												   || ntohs(get_u_int16_t(packet->payload, 0)) == 0x0165))) {
			flow->l4.udp.aimini_stage = 6;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 6.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 6 && ((packet->payload_packet_len == 136
												&& ((ntohs(get_u_int16_t(packet->payload, 0)) == 0x0165)
													|| ntohs(get_u_int16_t(packet->payload, 0)) == 0x01c9))
											   || (packet->payload_packet_len == 32
												   && ntohs(get_u_int16_t(packet->payload, 0)) == 0x01ca))) {
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG,
					"found aimini (136, 0x01c9), (136, 0x01c9)," "(136, 0x01c9),(136, 0x01c9 || 32, 0x01ca).\n");
			ndpi_int_aimini_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}

		/* third packet chronology: (len, value): (88, 0x0101), (88, 0x0101),(88, 0x0101),(88, 0x0101) */

		if (flow->l4.udp.aimini_stage == 7 && packet->payload_packet_len == 88
			&& ntohs(get_u_int16_t(packet->payload, 0)) == 0x0101) {
			flow->l4.udp.aimini_stage = 8;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 8.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 8
			&& (packet->payload_packet_len == 88 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x0101)) {
			flow->l4.udp.aimini_stage = 9;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 9.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 9
			&& (packet->payload_packet_len == 88 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x0101)) {
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG,
					"found aimini (88, 0x0101), (88, 0x0101)," "(88, 0x0101),(88, 0x0101).\n");
			ndpi_int_aimini_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}

		/* fourth packet chronology: (len, value): (104, 0x0102), (104, 0x0102), (104, 0x0102), (104, 0x0102) */

		if (flow->l4.udp.aimini_stage == 10 && packet->payload_packet_len == 104
			&& ntohs(get_u_int16_t(packet->payload, 0)) == 0x0102) {
			flow->l4.udp.aimini_stage = 11;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 11.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 11
			&& (packet->payload_packet_len == 104 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x0102)) {
			flow->l4.udp.aimini_stage = 12;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 12.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 12
			&& ((packet->payload_packet_len == 104 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x0102)
				|| (packet->payload_packet_len == 32 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x01ca))) {
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG,
					"found aimini (104, 0x0102), (104, 0x0102), " "(104, 0x0102), (104, 0x0102).\n");
			ndpi_int_aimini_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}

		/* fifth packet chronology (len, value): (32,0x01ca), (32,0x01ca), (32,0x01ca), ((136, 0x0166) || (32,0x01ca)) */

		if (flow->l4.udp.aimini_stage == 13 && packet->payload_packet_len == 32
			&& ntohs(get_u_int16_t(packet->payload, 0)) == 0x01ca) {
			flow->l4.udp.aimini_stage = 14;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 14.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 14
			&& ((packet->payload_packet_len == 32 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x01ca)
				|| (packet->payload_packet_len == 136 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x0166))) {
			flow->l4.udp.aimini_stage = 15;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 15.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 15
			&& ((packet->payload_packet_len == 136 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x0166)
				|| (packet->payload_packet_len == 32 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x01ca))) {
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG,
					"found aimini (32,0x01ca), (32,0x01ca), (32,0x01ca), ((136, 0x0166)||(32,0x01ca)).\n");
			ndpi_int_aimini_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}

		/* sixth packet chronology (len, value): (16, 0x010c), (16, 0x010c), (16, 0x010c), (16, 0x010c) */

		if (flow->l4.udp.aimini_stage == 16 && packet->payload_packet_len == 16
			&& ntohs(get_u_int16_t(packet->payload, 0)) == 0x010c) {
			flow->l4.udp.aimini_stage = 17;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 17.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 17
			&& (packet->payload_packet_len == 16 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x010c)) {
			flow->l4.udp.aimini_stage = 18;
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "stage = 18.\n");
			return;
		}
		if (flow->l4.udp.aimini_stage == 18
			&& (packet->payload_packet_len == 16 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x010c)) {
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG,
					"found aimini (16, 0x010c), (16, 0x010c), (16, 0x010c), (16, 0x010c).\n");
			ndpi_int_aimini_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
			return;
		}
	} else if (packet->tcp != NULL) {
		if ((packet->payload_packet_len > NDPI_STATICSTRING_LEN("GET /player/") &&
			 (memcmp(packet->payload, "GET /player/", NDPI_STATICSTRING_LEN("GET /player/")) == 0)) ||
			(packet->payload_packet_len > NDPI_STATICSTRING_LEN("GET /play/?fid=") &&
			 (memcmp(packet->payload, "GET /play/?fid=", NDPI_STATICSTRING_LEN("GET /play/?fid=")) == 0))) {
			NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "HTTP packet detected.\n");
			ndpi_parse_packet_line_info(ndpi_struct, flow);
			if (packet->host_line.ptr != NULL && packet->host_line.len > 11
				&& (memcmp(&packet->host_line.ptr[packet->host_line.len - 11], ".aimini.net", 11) == 0)) {
				NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "AIMINI HTTP traffic detected.\n");
				ndpi_int_aimini_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
				return;
			}
		}
		if (packet->payload_packet_len > 100) {
			if (memcmp(packet->payload, "GET /", NDPI_STATICSTRING_LEN("GET /")) == 0) {
				if (memcmp(&packet->payload[NDPI_STATICSTRING_LEN("GET /")], "play/",
						   NDPI_STATICSTRING_LEN("play/")) == 0 ||
					memcmp(&packet->payload[NDPI_STATICSTRING_LEN("GET /")], "download/",
						   NDPI_STATICSTRING_LEN("download/")) == 0) {
					ndpi_parse_packet_line_info(ndpi_struct, flow);
					if (is_special_aimini_host(packet->host_line) == 1) {
						NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG,
								"AIMINI HTTP traffic detected.\n");
						ndpi_int_aimini_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
						return;
					}
				}
			} else if (memcmp(packet->payload, "POST /", NDPI_STATICSTRING_LEN("POST /")) == 0) {
				if (memcmp(&packet->payload[NDPI_STATICSTRING_LEN("POST /")], "upload/",
						   NDPI_STATICSTRING_LEN("upload/")) == 0) {
					ndpi_parse_packet_line_info(ndpi_struct, flow);
					if (is_special_aimini_host(packet->host_line) == 1) {
						NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG,
								"AIMINI HTTP traffic detected.\n");
						ndpi_int_aimini_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
						return;
					}
				}
			}
		}
	}

	NDPI_LOG(NDPI_PROTOCOL_AIMINI, ndpi_struct, NDPI_LOG_DEBUG, "exclude aimini.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_AIMINI);

}
#endif
