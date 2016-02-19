/*
 * mqtt.c
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
#ifdef NDPI_PROTOCOL_MQTT

/**
 * The type of control messages in mqtt version 3.1.1
 * see http://docs.oasis-open.org/mqtt/mqtt/v3.1.1
 */
enum MQTT_PACKET_TYPES {
	CONNECT = 1,
	CONNACK = 2,
	PUBLISH = 3,
	PUBACK = 4,
	PUBREC = 5,
	PUBREL = 6,
	PUBCOMP = 7,
	SUBSCRIBE = 8,
	SUBACK = 9,
	UNSUBSCRIBE = 10,
	UNSUBACK = 11,
	PINGREQ = 12,
	PINGRESP = 13,
	DISCONNECT = 14
};


/**
 * Entry point when protocol is identified.
 */
static void ndpi_int_mqtt_add_connection (struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow)
{
	ndpi_set_detected_protocol(ndpi_struct,flow,NDPI_PROTOCOL_MQTT,NDPI_PROTOCOL_UNKNOWN);
	NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt found.\n");
}

/**
 * Dissector function that searches Mqtt headers
 */
void ndpi_search_mqtt (struct ndpi_detection_module_struct *ndpi_struct,
		       struct ndpi_flow_struct *flow)
{
	NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt search called...\n");
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
		return;
	}
	NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt detection...\n");
	// searching for request
	NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "====>>>> Mqtt header: %4x%4x%4x%4x [len: %u]\n",
			packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3], packet->payload_packet_len);
	if (packet->payload_packet_len < 2) {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt .. mandatory header not found!\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	}
	// we first extract the packet type
	u_int8_t pt = (u_int8_t) ((packet->payload[0] & 0xF0) >> 4);
	if ((pt == 0) || (pt == 15)) {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt .. invalid packet type!\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	}
	u_int8_t flags = (u_int8_t) (packet->payload[0] & 0x0F);
	// first stage verification
	if ((((pt == CONNECT) || (pt == CONNACK) || (pt == PUBACK) || (pt == PUBREC) ||
		  (pt == PUBCOMP) || (pt = SUBACK) || (pt == UNSUBACK) || (pt == PINGREQ) ||
		  (pt == PINGRESP) || (pt == DISCONNECT)))  && (flags != 0)) {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt invalid Packet-Flag combination [%d]\n",pt);
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	}
	if (((pt == PUBREL) || (pt == SUBSCRIBE) || (pt == UNSUBSCRIBE)) && (flags != 2)) {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt invalid Packet-Flag combination [%d]\n",pt);
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	}
	// second stage verification (no payload)
	if (((pt == CONNACK) || (pt == PUBACK) || (pt == PUBREL) ||
		(pt == PUBREC) || (pt == PUBCOMP) || (pt == UNSUBACK)) && (packet->payload_packet_len > 4)){
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt invalid Packet-Length [%d]\n",pt);
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	} else {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt found [%d]\n",pt);
		ndpi_int_mqtt_add_connection(ndpi_struct,flow);
		return;
	}
	if (((pt == PINGREQ) || (pt == PINGRESP) || (pt == DISCONNECT)) && (packet->payload_packet_len > 2))
	{
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt invalid Packet-Length [%d]\n",pt);
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	} else {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt found [%d]\n",pt);
		ndpi_int_mqtt_add_connection(ndpi_struct,flow);
		return;
	}
	// third stage verification (payload)
	if ((pt == CONNECT) && (memcmp(&(packet->payload[4]),"MQTT",4) == 0) ){
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt found [%d]\n",pt);
		ndpi_int_mqtt_add_connection(ndpi_struct,flow);
		return;
	} else {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt [%d]\n",pt);
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	}
	if (pt == PUBLISH){
		u_int8_t qos = (u_int8_t) (flags & 0x06);
		if (((qos == 1) || (qos == 2)) && (packet->payload_packet_len < 4)){ // at least topic + pkt identifier
			NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt [%d]\n",pt);
			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
			return;
		}
		if ((qos == 0) && (packet->payload_packet_len < 3)){ // at least topic
			NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt [%d]\n",pt);
			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
			return;
		}
		if ((qos == 3)){ // this should never happen
			NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt[%d]\n",pt);
			NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
			return;
		}
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt found PUBLISH\n",pt);
		ndpi_int_mqtt_add_connection(ndpi_struct,flow);
		return;

	}
	if ((pt == SUBSCRIBE) && (packet->payload_packet_len < 8)){ // at least one topic+filter is required in the payload
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt [%d]\n",pt);
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	} else {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt found [%d]\n",pt);
		ndpi_int_mqtt_add_connection(ndpi_struct,flow);
		return;
	}

	if ((pt == SUBACK ) && (packet->payload_packet_len <5 )){ // must have at least a response code
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt [%d]\n",pt);
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	} else {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt found [%d]\n",pt);
		ndpi_int_mqtt_add_connection(ndpi_struct,flow);
		return;
	}

	if ((pt == UNSUBSCRIBE) && (packet->payload_packet_len < 7)) { // at least a topic
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt\n",pt);
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	} else {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt found [%d]\n",pt);
		ndpi_int_mqtt_add_connection(ndpi_struct,flow);
		return;
	}

	NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt ...\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
	return;
}
/**
 * Entry point for the ndpi library
 */
void init_mqtt_dissector (struct ndpi_detection_module_struct *ndpi_struct,
		     u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Mqtt dissector init...\n");
  ndpi_set_bitmask_protocol_detection ("MQTT", ndpi_struct, detection_bitmask, *id,
				       NDPI_PROTOCOL_MQTT,
				       ndpi_search_mqtt,
				       NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				       SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);
  *id +=1;
}

#endif // NDPI_PROTOCOL_MQTT

