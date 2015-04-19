/*
 * pplive.c
 *
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
 * 
 * The signature is mostly based on the Libprotoident library
 * except the detection of HTTP Steam flows.
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

#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_PPLIVE
static void ndpi_int_pplive_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_PPLIVE, NDPI_REAL_PROTOCOL);
}

static void ndpi_check_pplive_udp1(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;
	
	/* Check if we so far detected the protocol in the request or not. */
	if (flow->pplive_stage1 == 0) {
		NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE stage 0: \n");
		
		if ((payload_len > 0) && match_first_bytes(packet->payload, "\xe9\x03\x41\x01")) {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Possible PPLIVE request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pplive_stage1 = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
			return;
		}
		
		if ((payload_len > 0) && match_first_bytes(packet->payload, "\xe9\x03\x42\x01")) {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Possible PPLIVE request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pplive_stage1 = packet->packet_direction + 3; // packet_direction 0: stage 3, packet_direction 1: stage 4
			return;
		}
		
		if ((payload_len > 0) && match_first_bytes(packet->payload, "\x1c\x1c\x32\x01")) {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Possible PPLIVE request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pplive_stage1 = packet->packet_direction + 5; // packet_direction 0: stage 5, packet_direction 1: stage 6
			return;
		}			

	} else if ((flow->pplive_stage1 == 1) || (flow->pplive_stage1 == 2)) {
		NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE stage %u: \n", flow->pplive_stage1);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pplive_stage1 - packet->packet_direction) == 1) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len > 0) && (match_first_bytes(packet->payload, "\xe9\x03\x42\x01") || match_first_bytes(packet->payload, "\xe9\x03\x41\x01"))) {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Found PPLIVE.\n");
			ndpi_int_pplive_add_connection(ndpi_struct, flow);
		} else {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to PPLIVE, resetting the stage to 0...\n");
			flow->pplive_stage1 = 0;
		}
		
	} else if ((flow->pplive_stage1 == 3) || (flow->pplive_stage1 == 4)) {
		NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE stage %u: \n", flow->pplive_stage1);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pplive_stage1 - packet->packet_direction) == 3) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len > 0) && match_first_bytes(packet->payload, "\xe9\x03\x41\x01")) {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Found PPLIVE.\n");
			ndpi_int_pplive_add_connection(ndpi_struct, flow);
		} else {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to PPLIVE, resetting the stage to 0...\n");
			flow->pplive_stage1 = 0;
		}
	} else if ((flow->pplive_stage1 == 5) || (flow->pplive_stage1 == 6)) {
		NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE stage %u: \n", flow->pplive_stage1);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pplive_stage1 - packet->packet_direction) == 5) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len > 0) && match_first_bytes(packet->payload, "\x1c\x1c\x32\x01")) {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Found PPLIVE.\n");
			ndpi_int_pplive_add_connection(ndpi_struct, flow);
		} else {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to PPLIVE, resetting the stage to 0...\n");
			flow->pplive_stage1 = 0;
		}
	}
		
}

static void ndpi_check_pplive_udp2(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;

	/* Check if we so far detected the protocol in the request or not. */
	if (flow->pplive_stage2 == 0) {
		NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE stage 0: \n");
		
		if ((payload_len == 57) && match_first_bytes(packet->payload, "\xe9\x03\x41\x01")) {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Possible PPLIVE request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pplive_stage2 = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
		}

	} else {
		NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE stage %u: \n", flow->pplive_stage2);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pplive_stage2 - packet->packet_direction) == 1) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if (payload_len == 0) {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Found PPLIVE.\n");
			ndpi_int_pplive_add_connection(ndpi_struct, flow);
		} else {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to PPLIVE, resetting the stage to 0...\n");
			flow->pplive_stage2 = 0;
		}
		
	}
}

static void ndpi_check_pplive_udp3(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;
	
	/* Check if we so far detected the protocol in the request or not. */
	if (flow->pplive_stage3 == 0) {
		NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE stage 0: \n");
		
		if ((payload_len == 94) && (packet->udp->dest == htons(5041) || packet->udp->source == htons(5041) || packet->udp->dest == htons(8303) || packet->udp->source == htons(8303))) {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Possible PPLIVE request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pplive_stage3 = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
			return;
		}	

	} else {
		NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE stage %u: \n", flow->pplive_stage3);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pplive_stage3 - packet->packet_direction) == 1) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len == 0) || (payload_len == 49) ||(payload_len == 94)) {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Found PPLIVE.\n");
			ndpi_int_pplive_add_connection(ndpi_struct, flow);
		} else {
			NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to PPLIVE, resetting the stage to 0...\n");
			flow->pplive_stage3 = 0;
		}
	}
		
}

void ndpi_search_pplive(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	/* Break after 20 packets. */
	if (flow->packet_counter > 20) {
		NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "Exclude PPLIVE.\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_PPLIVE);
		return;
	}

	if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_PPLIVE) {
		return;
	}

	NDPI_LOG(NDPI_PROTOCOL_PPLIVE, ndpi_struct, NDPI_LOG_DEBUG, "PPLIVE detection...\n");
	ndpi_check_pplive_udp1(ndpi_struct, flow);
	
	if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_PPLIVE) {
	    return;
	}
	
	ndpi_check_pplive_udp2(ndpi_struct, flow);
	
	if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_PPLIVE) {
	    return;
	}
	
	ndpi_check_pplive_udp3(ndpi_struct, flow);
}

#endif
