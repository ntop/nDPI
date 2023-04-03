/*
 * rocket_league.c
 *
 * Copyright (C) 2020 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ROCKET_LEAGUE

#include "ndpi_api.h"

/*
Note 1:

A statistical analysis was performed on several suspected UDP flows.

Inter-arrival time in ms:

flow avg: 8.6 - 8.7
flow std dev: 8.9 - 9.8
client -> server avg: 16.2 - 16.3
server -> client avg: 16.4 - 16.8

Packet length (including headers):
client -> server avg: 124.3 - 127.1
client -> server std dev: 10.0 - 11.1
server -> client avg: 153.8 - 156.9
server -> client std dev: 39.0 - 41.2

Ultimately this data was not used for classification because too many packets
were required before the statistics settled into a narrow enough range.

Note 2:

The OpenVPN signature will classify with packet_num = 1, payload_len = 80,
opcode = 60. This is a weak signature and conflicts with some (suspected) 
Rocket League flows.
*/

static void ndpi_search_rocket_league(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {

    struct ndpi_packet_struct *const packet = &ndpi_struct->packet;

    printf("rocket league search direction = %d payload_len = %d packet_counter = %d num_processed_pkts = %d iat = %ld\n",
		packet->packet_direction, packet->payload_packet_len, flow->packet_counter, flow->num_processed_pkts);

	// If this is too restrictive increase upper limit
	if (packet->payload_packet_len < 48 || packet->payload_packet_len > 496) {
   		printf("not rocket league match 0\n");
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
		return;
	}

	if (packet->payload_packet_len < 48) {
   		printf("not rocket league match 2\n");
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
		return;
	}

    if (flow->packet_counter == 1) {
		if (packet->packet_direction == 0 && packet->payload_packet_len == 80) {
			return; //continue inspecting
		} else {
    		printf("not rocket league match 1\n");
			NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
			return;
		}
	}

    if (flow->packet_counter == 2 || flow->packet_counter == 3) {
		if (packet->packet_direction == 0 && packet->payload_packet_len == 48) {
			return; //continue inspecting
		} else {
    		printf("not rocket league match 2\n");
			NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
			return;
		}
	}

	if (flow->packet_counter >= 10) {
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ROCKET_LEAGUE, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
	}
}

void init_rocket_league_dissector(struct ndpi_detection_module_struct
                                  *ndpi_struct, u_int32_t * id) {
    printf("rocket league init\n");
    ndpi_set_bitmask_protocol_detection("RocketLeague", ndpi_struct, *id,
                                        NDPI_PROTOCOL_ROCKET_LEAGUE,
                                        ndpi_search_rocket_league,
                                        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                        SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                        ADD_TO_DETECTION_BITMASK);
    *id += 1;
}
