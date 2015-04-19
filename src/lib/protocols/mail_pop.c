/*
 * mail_pop.c
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

#ifdef NDPI_PROTOCOL_MAIL_POP

#define POP_BIT_AUTH		0x0001
#define POP_BIT_APOP		0x0002
#define POP_BIT_USER		0x0004
#define POP_BIT_PASS		0x0008
#define POP_BIT_CAPA		0x0010
#define POP_BIT_LIST		0x0020
#define POP_BIT_STAT		0x0040
#define POP_BIT_UIDL		0x0080
#define POP_BIT_RETR		0x0100
#define POP_BIT_DELE		0x0200
#define POP_BIT_STLS		0x0400


static void ndpi_int_mail_pop_add_connection(struct ndpi_detection_module_struct
											   *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MAIL_POP, NDPI_REAL_PROTOCOL);
}


static int ndpi_int_mail_pop_check_for_client_commands(struct ndpi_detection_module_struct
														 *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//  struct ndpi_id_struct         *src=ndpi_struct->src;
//  struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (packet->payload_packet_len > 4) {
		if ((packet->payload[0] == 'A' || packet->payload[0] == 'a')
			&& (packet->payload[1] == 'U' || packet->payload[1] == 'u')
			&& (packet->payload[2] == 'T' || packet->payload[2] == 't')
			&& (packet->payload[3] == 'H' || packet->payload[3] == 'h')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_AUTH;
			return 1;
		} else if ((packet->payload[0] == 'A' || packet->payload[0] == 'a')
				   && (packet->payload[1] == 'P' || packet->payload[1] == 'p')
				   && (packet->payload[2] == 'O' || packet->payload[2] == 'o')
				   && (packet->payload[3] == 'P' || packet->payload[3] == 'p')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_APOP;
			return 1;
		} else if ((packet->payload[0] == 'U' || packet->payload[0] == 'u')
				   && (packet->payload[1] == 'S' || packet->payload[1] == 's')
				   && (packet->payload[2] == 'E' || packet->payload[2] == 'e')
				   && (packet->payload[3] == 'R' || packet->payload[3] == 'r')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_USER;
			return 1;
		} else if ((packet->payload[0] == 'P' || packet->payload[0] == 'p')
				   && (packet->payload[1] == 'A' || packet->payload[1] == 'a')
				   && (packet->payload[2] == 'S' || packet->payload[2] == 's')
				   && (packet->payload[3] == 'S' || packet->payload[3] == 's')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_PASS;
			return 1;
		} else if ((packet->payload[0] == 'C' || packet->payload[0] == 'c')
				   && (packet->payload[1] == 'A' || packet->payload[1] == 'a')
				   && (packet->payload[2] == 'P' || packet->payload[2] == 'p')
				   && (packet->payload[3] == 'A' || packet->payload[3] == 'a')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_CAPA;
			return 1;
		} else if ((packet->payload[0] == 'L' || packet->payload[0] == 'l')
				   && (packet->payload[1] == 'I' || packet->payload[1] == 'i')
				   && (packet->payload[2] == 'S' || packet->payload[2] == 's')
				   && (packet->payload[3] == 'T' || packet->payload[3] == 't')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_LIST;
			return 1;
		} else if ((packet->payload[0] == 'S' || packet->payload[0] == 's')
				   && (packet->payload[1] == 'T' || packet->payload[1] == 't')
				   && (packet->payload[2] == 'A' || packet->payload[2] == 'a')
				   && (packet->payload[3] == 'T' || packet->payload[3] == 't')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_STAT;
			return 1;
		} else if ((packet->payload[0] == 'U' || packet->payload[0] == 'u')
				   && (packet->payload[1] == 'I' || packet->payload[1] == 'i')
				   && (packet->payload[2] == 'D' || packet->payload[2] == 'd')
				   && (packet->payload[3] == 'L' || packet->payload[3] == 'l')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_UIDL;
			return 1;
		} else if ((packet->payload[0] == 'R' || packet->payload[0] == 'r')
				   && (packet->payload[1] == 'E' || packet->payload[1] == 'e')
				   && (packet->payload[2] == 'T' || packet->payload[2] == 't')
				   && (packet->payload[3] == 'R' || packet->payload[3] == 'r')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_RETR;
			return 1;
		} else if ((packet->payload[0] == 'D' || packet->payload[0] == 'd')
				   && (packet->payload[1] == 'E' || packet->payload[1] == 'e')
				   && (packet->payload[2] == 'L' || packet->payload[2] == 'l')
				   && (packet->payload[3] == 'E' || packet->payload[3] == 'e')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_DELE;
			return 1;
		} else if ((packet->payload[0] == 'S' || packet->payload[0] == 's')
				   && (packet->payload[1] == 'T' || packet->payload[1] == 't')
				   && (packet->payload[2] == 'L' || packet->payload[2] == 'l')
				   && (packet->payload[3] == 'S' || packet->payload[3] == 's')) {
			flow->l4.tcp.pop_command_bitmask |= POP_BIT_STLS;
			return 1;
		}
	}
	return 0;
}



void ndpi_search_mail_pop_tcp(struct ndpi_detection_module_struct
								*ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//  struct ndpi_id_struct         *src=ndpi_struct->src;
//  struct ndpi_id_struct         *dst=ndpi_struct->dst;
	u_int8_t a = 0;
	u_int8_t bit_count = 0;

	NDPI_LOG(NDPI_PROTOCOL_MAIL_POP, ndpi_struct, NDPI_LOG_DEBUG, "search mail_pop\n");



	if ((packet->payload_packet_len > 3
		 && (packet->payload[0] == '+' && (packet->payload[1] == 'O' || packet->payload[1] == 'o')
			 && (packet->payload[2] == 'K' || packet->payload[2] == 'k')))
		|| (packet->payload_packet_len > 4
			&& (packet->payload[0] == '-' && (packet->payload[1] == 'E' || packet->payload[1] == 'e')
				&& (packet->payload[2] == 'R' || packet->payload[2] == 'r')
				&& (packet->payload[3] == 'R' || packet->payload[3] == 'r')))) {
		// +OK or -ERR seen
		flow->l4.tcp.mail_pop_stage += 1;
	} else if (!ndpi_int_mail_pop_check_for_client_commands(ndpi_struct, flow)) {
		goto maybe_split_pop;
	}

	if (packet->payload_packet_len > 2 && ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {

		// count the bits set in the bitmask
		if (flow->l4.tcp.pop_command_bitmask != 0) {
			for (a = 0; a < 16; a++) {
				bit_count += (flow->l4.tcp.pop_command_bitmask >> a) & 0x01;
			}
		}

		NDPI_LOG(NDPI_PROTOCOL_MAIL_POP, ndpi_struct, NDPI_LOG_DEBUG,
				"mail_pop +OK/-ERR responses: %u, unique commands: %u\n", flow->l4.tcp.mail_pop_stage, bit_count);

		if ((bit_count + flow->l4.tcp.mail_pop_stage) >= 3) {
			if (flow->l4.tcp.mail_pop_stage > 0) {
				NDPI_LOG(NDPI_PROTOCOL_MAIL_POP, ndpi_struct, NDPI_LOG_DEBUG, "mail_pop identified\n");
				ndpi_int_mail_pop_add_connection(ndpi_struct, flow);
				return;
			} else {
				return;
			}
		} else {
			return;
		}

	} else {
		// first part of a split packet
		NDPI_LOG(NDPI_PROTOCOL_MAIL_POP, ndpi_struct, NDPI_LOG_DEBUG,
				"mail_pop command without line ending -> skip\n");
		return;
	}


  maybe_split_pop:

	if (((packet->payload_packet_len > 2 && ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a)
		 || flow->l4.tcp.pop_command_bitmask != 0 || flow->l4.tcp.mail_pop_stage != 0) && flow->packet_counter < 12) {
		// maybe part of a split pop packet
		NDPI_LOG(NDPI_PROTOCOL_MAIL_POP, ndpi_struct, NDPI_LOG_DEBUG,
				"maybe part of split mail_pop packet -> skip\n");
		return;
	}

	NDPI_LOG(NDPI_PROTOCOL_MAIL_POP, ndpi_struct, NDPI_LOG_DEBUG, "exclude mail_pop\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MAIL_POP);
}
#endif
