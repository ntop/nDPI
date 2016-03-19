/*
 * coap.c
 *
 * Copyright (C) 2016 Sorin Zamfir <sorin.zamfir@yahoo.com>
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
#ifdef NDPI_PROTOCOL_COAP

/**
 * Entry point when protocol is identified.
 */
static void ndpi_int_coap_add_connection (struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow)
{
  // not sure if this is accurate but coap runs on top of udp and should be connectionless
  ndpi_set_detected_protocol(ndpi_struct,flow,NDPI_PROTOCOL_COAP,NDPI_PROTOCOL_UNKNOWN);
  NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "CoAP found.\n");
}
/**
 * Dissector function that searches CoAP headers
 */
void ndpi_search_coap (struct ndpi_detection_module_struct *ndpi_struct,
		       struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
		return;
	}
	NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "CoAP detection...\n");
	// searching for request
	NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "====>>>> COAP header: %04x%04x%04x%04x [len: %u]\n",
			packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3], packet->payload_packet_len);
	// check if we have version bits
	if (packet->payload_packet_len < 4) {
		NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Coap .. mandatory header not found!\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_COAP);
		return;
	}
	// since this is always unsigned we could have spared the 0xF0 logical AND
	// vt = version and type (version is mandatory 1; type is either 0,1,2,3 )
	u_int8_t vt = (u_int8_t) ((packet->payload[0] & 0xF0) >> 4);
	if ((vt == 4) || (vt == 5) || (vt == 6) || (vt == 7)) {
		NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "Continuing Coap detection \n");
		// search for values 9 to 15 in the token length
		u_int8_t tkl = (u_int8_t) ((packet->payload[0] & 0x0F));
		if ((tkl >= 9) && (tkl <= 15)) {
			NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Coap .. invalid token length found!\n");
			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_COAP);
			return;
		}
		u_int8_t class = (u_int8_t) ((packet->payload[1] & 0xE0) >> 5);
		u_int8_t detail = (u_int8_t) ((packet->payload[1] & 0x1F));
		if ((class == 0) && (detail == 0) && (tkl == 0) && (packet->payload_packet_len == 4)) {
			NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "Coap found ... empty message\n");
			ndpi_int_coap_add_connection(ndpi_struct,flow);
			return;
		}
		if ((class == 0) && ((detail == 1) || (detail == 2 ) || (detail == 3 ) || (detail == 4 ))) {
			// we should probably search for options as well and payload for deeper inspection
			NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "Coap found ... req message\n");
			ndpi_int_coap_add_connection(ndpi_struct,flow);
			return;
		}
		if ((class == 2) || (class == 4) || (class == 5)) {
			// we should probably search for options as well and payload for deeper inspection
			NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "Coap found ... resp message\n");
			ndpi_int_coap_add_connection(ndpi_struct,flow);
			return;
		}
	}
	NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Coap ...\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_COAP);
	return;

}
/**
 * Entry point for the ndpi library
 */
void init_coap_dissector (struct ndpi_detection_module_struct *ndpi_struct,
		     u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection ("COAP", ndpi_struct, detection_bitmask, *id,
				       NDPI_PROTOCOL_COAP,
				       ndpi_search_coap,
				       NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				       SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);
  *id +=1;
}


#endif // NDPI_PROTOCOL_COAP
