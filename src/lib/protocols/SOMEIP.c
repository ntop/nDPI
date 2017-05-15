/*
 * SOMEIP.c
 *
 * Copyright (C) 2016 Sorin Zamfir <sorin.zamfir@yahoo.com>
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your omessage_typeion) any later version.
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
#ifdef NDPI_PROTOCOL_SOMEIP

/**
 * The type of control messages in mqtt version 3.1.1
 * see http://docs.oasis-open.org/mqtt/mqtt/v3.1.1
 */
enum SOMEIP_MESSAGE_TYPES {
	REQUEST = 0x00,
	REQUEST_NO_RETURN = 0x01,
	NOTIFICATION = 0x02,
	REQUEST_ACK = 0x40,
	REQUEST_NO_RETURN_ACK = 0x41,
	NOTIFICATION_ACK = 0x42,
	RESPONSE = 0x80,
	ERROR = 0x81,
	RESPONSE_ACK = 0xc0,
	ERROR_ACK = 0xc1
};

enum SOMEIP_RETURN_CODES {
	E_OK = 0x00,
	E_NOT_OK = 0x01,
	E_UNKNOWN_SERVICE = 0x02,
	E_UNKNOWN_METHOD = 0x03,
	E_NOT_READY = 0x04,
	E_NOT_REACHABLE = 0x05,
	E_TIMEOUT = 0x06,
	E_WRONG_PROTOCOL_VERSION = 0x07,
	E_WRONG_INTERFACE_VERSION = 0x08,
	E_MALFORMED_MESSAGE = 0x09,
	E_WRONG_MESSAGE_TYPE = 0x0a
};

enum SPECIAL_MESSAGE_IDS {
	MSG_MAGIC_COOKIE = 0xffff0000,
	MSG_MAGIC_COOKIE_ACK = 0xffff8000,
	MSG_SD = 0xffff8100
};


/**
 * Entry point when protocol is identified.
 */
static void ndpi_int_someip_add_connection (struct ndpi_detection_module_struct *ndpi_struct,
		struct ndpi_flow_struct *flow)
{
	ndpi_set_detected_protocol(ndpi_struct,flow,NDPI_PROTOCOL_SOMEIP,NDPI_PROTOCOL_UNKNOWN);
	NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "SOME/IP found.\n");
}

/**
 * Dissector function that searches SOME/IP headers
 */
void ndpi_search_someip (struct ndpi_detection_module_struct *ndpi_struct,
		struct ndpi_flow_struct *flow)
{

	//####Maybe check carrier protocols?####
	NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "SOME/IP search called...\n");
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
		return;
	}
	/*NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "SOME/IP detection...\n");
	if (flow->packet_counter > 10) {
		NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding SOME/IP .. mandatory header not found!\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOMEIP);
		return;
	}
	####This block drops flows with over 10 packets. Why? Probably just an auto-drop in case nothing else catches it. Necessary for SOME/IP? Good question.####
	*/

	NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "====>>>> SOME/IP Service ID: %02x%02x%02x%02x [len: %u]\n",
			packet->payload[3], packet->payload[2], packet->payload[1], packet->payload[0], packet->payload_packet_len);
	//####I switched the endianity on these since the Message ID is 32 bit. Might be a wrong move?####
	if (packet->payload_packet_len < 16) {
		NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding SOME/IP .. mandatory header not found (not enough data for all fields)\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOMEIP);
		return;
	}
	/*if (packet->payload_packet_len > 258) {
		NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding SOME/IP .. maximum packet size exceeded!\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOMEIP);
		return;
	}
	####Maximum packet size in SOMEIP depends on the carrier protocol, and I'm not certain how well enforced it is, so let's leave that for round 2####
	*/


	
	// we extract the remaining length
	u_int32_t someip_len = (u_int32_t) (packet->payload[4]+(packet->payload[5]<<8)+(packet->payload[6]<<16)+(packet->payload[7]<<24));
	if (packet->payload_packet_len != (someip_len + 8)) {
		NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding SOME/IP .. Length field invalid!\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOMEIP);
		return;
	}


	// check protocol version. ####CHECK IF ENDIANITY IS CORRECT####
	u_int8_t protocol_version = (u_int8_t) (packet->payload[15]);
	NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG,"====>>>> SOME/IP protocol version: [%d]\n",protocol_version);
	if (protocol_version != 0x01){
		NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding SOME/IP .. invalid protocol version!\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOMEIP);
		return;
	}

	//####Read Interface Version, for later use. CHECK IF ENDIANITY IS CORRECT####
	u_int8_t interface_version = (packet->payload[14]);
	

	// we extract the message type. ####CHECK IF ENDIANITY IS CORRECT####
	u_int8_t message_type = (u_int8_t) (packet->payload[13]);
	NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG,"====>>>> SOME/IP message type: [%d]\n",message_type);
	if ((message_type != 0x00) && (message_type != 0x01) && (message_type != 0x02) && (message_type != 0x40) && (message_type != 0x41) && 
					(message_type != 0x42) && (message_type != 0x80) && (message_type != 0x81) && (message_type != 0xc0) && (message_type != 0xc1)) {
		NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding SOME/IP .. invalid message type!\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOMEIP);
		return;
	}

	// we extract the return code. ####CHECK IF ENDIANITY IS CORRECT####
	u_int8_t return_code = (u_int8_t) (packet->payload[12]);
	NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG,"====>>>> SOME/IP return code: [%d]\n",return_code);
	if ((return_code > 0x3f)) {
		NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding SOME/IP .. invalid return code!\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOMEIP);
		return;
	}
	
	//we extract the Message ID and Request ID and check for special cases
	u_int32_t message_id = (u_int32_t) (packet->payload[0]+(packet->payload[1]<<8)+(packet->payload[2]<<16)+(packet->payload[3]<<24));
	u_int32_t request_id = (u_int32_t) (packet->payload[8]+(packet->payload[9]<<8)+(packet->payload[10]<<16)+(packet->payload[11]<<24));
	
 	if (message_id == MSG_MAGIC_COOKIE){
		if ((someip_len == 0x08) && (request_id == 0xDEADBEEF) && (interface_version == 0x01) &&
					(message_type == 0x01) && (return_code == 0x00)){
			NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "SOME/IP found Magic Cookie\n",message_type);
			ndpi_int_someip_add_connection(ndpi_struct,flow);
			return;
		}											
		else{
			NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding SOME/IP, invalid header for Magic Cookie\n");
			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOMEIP);
			return;
		}
 	}
	
	if (message_id == MSG_MAGIC_COOKIE_ACK){
		if ((someip_len == 0x08) && (request_id == 0xDEADBEEF) && (interface_version == 0x01) &&
					(message_type == 0x02) && (return_code == 0x00)){
			NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "SOME/IP found Magic Cookie ACK\n",message_type);
			ndpi_int_someip_add_connection(ndpi_struct,flow);
			return;
		}											
		else{
			NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "Excluding SOME/IP, invalid header for Magic Cookie ACK\n");
			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOMEIP);
			return;
		}
 	}

	if (message_id == MSG_SD){
		//####Service Discovery message. Fill in later!####
	}

	//Filtering by port as per request. This is PURELY for demo purposes and the rest of the check must be filled in later on!
	if (packet->l4_protocol == IPPROTO_UDP){
		if ((packet->udp->dest == ntohs(30491)) || (packet->udp->dest == ntohs(30501)) || (packet->udp->dest == ntohs(30490))) {
			NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "SOME/IP found\n",message_type);
			ndpi_int_someip_add_connection(ndpi_struct,flow);
		}
	}
	if (packet->l4_protocol == IPPROTO_TCP){
		if ((packet->tcp->dest == ntohs(30491)) || (packet->tcp->dest == ntohs(30501))) {
			NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "SOME/IP found\n",message_type);
			ndpi_int_someip_add_connection(ndpi_struct,flow);
		}
	}
	



	NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "Reached the end without confirming SOME/IP ...\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SOMEIP);
	return;
}
/**
 * Entry point for the ndpi library
 */
void init_someip_dissector (struct ndpi_detection_module_struct *ndpi_struct,
		u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
	NDPI_LOG(NDPI_PROTOCOL_SOMEIP, ndpi_struct, NDPI_LOG_DEBUG, "SOME/IP dissector init...\n");
	ndpi_set_bitmask_protocol_detection ("SOME/IP", ndpi_struct, detection_bitmask, *id,
			NDPI_PROTOCOL_SOMEIP,
			ndpi_search_someip,
			NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
			SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);
	*id +=1;
}

#endif // NDPI_PROTOCOL_SOMEIP

