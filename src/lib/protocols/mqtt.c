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
	NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "====>>>> Mqtt header: %04x%04x%04x%04x [len: %u]\n",
			packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3], packet->payload_packet_len);
	if (packet->payload_packet_len < 2) {
		NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt .. mandatory header not found!\n");
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
		return;
	}
	u_int8_t pt = (u_int8_t) (packet->payload[0]);

	NDPI_LOG(NDPI_PROTOCOL_MQTT, ndpi_struct, NDPI_LOG_DEBUG, "Excluding Mqtt ...\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MQTT);
	return;
	//TODO
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

