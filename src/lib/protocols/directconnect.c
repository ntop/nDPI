/*
 * directconnect.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-22 - ntop.org
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


#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DIRECTCONNECT

#include "ndpi_api.h"


//#define NDPI_DEBUG_DIRECTCONNECT
//#define NDPI_DIRECTCONNECT_PORT_DEBUG
//#define NDPI_DEBUG_DIRECTCONNECT_CONN


#define DIRECT_CONNECT_TYPE_HUB  0
#define DIRECT_CONNECT_TYPE_PEER 1
#define DIRECT_CONNECT_ADC_PEER  2

static u_int32_t skip_unknown_headers(const u_int8_t * payload, u_int32_t payload_len, u_int32_t pos)
{
  u_int32_t i = pos;
  while (i < payload_len && payload[i] != 0x0a)
    i++;

  i++;
  return i;

}

static u_int16_t parse_binf_message(struct ndpi_detection_module_struct
				    *ndpi_struct, const u_int8_t * payload, uint32_t payload_len)
{
  u_int32_t i = 4;
  u_int16_t bytes_read = 0;
  u_int16_t ssl_port = 0;
  while (i < payload_len) {
    i = skip_unknown_headers(payload, payload_len, i);
    if((i + 30) < payload_len) {
      if(memcmp(&payload[i], "DCTM", 4) == 0) {
	if(memcmp(&payload[i + 15], "ADCS", 4) == 0) {
	  ssl_port = ntohs_ndpi_bytestream_to_number(&payload[i + 25], 5, &bytes_read);
	  NDPI_LOG_DBG2(ndpi_struct, "DC ssl port parsed %d\n", ssl_port);
	}
      }
    } else {
      break;
    }

  }
  return ssl_port;
}

static void ndpi_int_directconnect_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
						  struct ndpi_flow_struct *flow,
						  const u_int8_t connection_type)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DIRECTCONNECT, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_directconnect_tcp(struct ndpi_detection_module_struct *ndpi_struct,
					  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
	
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_DIRECTCONNECT) {
    if(packet->payload_packet_len >= 40 && memcmp(&packet->payload[0], "BINF", 4) == 0) {
      parse_binf_message(ndpi_struct,
			 &packet->payload[4],
			 packet->payload_packet_len - 4);
    }
    
    return;

  }

  if(flow->directconnect_stage == 0) {

    if(packet->payload_packet_len > 6) {
      if(packet->payload[0] == '$'
	  && packet->payload[packet->payload_packet_len - 1] == '|'
	  && (memcmp(&packet->payload[1], "Lock ", 5) == 0)) {
	NDPI_LOG_DBG2(ndpi_struct, "maybe first dc connect to hub  detected\n");
	flow->directconnect_stage = 1;
	return;
      }
      if(packet->payload_packet_len > 7
	  && packet->payload[0] == '$'
	  && packet->payload[packet->payload_packet_len - 1] == '|'
	  && (memcmp(&packet->payload[1], "MyNick ", 7) == 0)) {
	NDPI_LOG_DBG2(ndpi_struct, "maybe first dc connect between peers  detected\n");
	flow->directconnect_stage = 2;
	return;
      }

    }
    if(packet->payload_packet_len >= 11) {
      /* did not see this pattern in any trace */
      if(memcmp(&packet->payload[0], "HSUP ADBAS0", 11) == 0
	  || memcmp(&packet->payload[0], "HSUP ADBASE", 11) == 0) {
	NDPI_LOG_INFO(ndpi_struct, "found DC HSUP ADBAS0 E\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_TYPE_HUB);
	return;
	/* did not see this pattern in any trace */
      } else if(memcmp(&packet->payload[0], "CSUP ADBAS0", 11) == 0 ||
		 memcmp(&packet->payload[0], "CSUP ADBASE", 11) == 0) {
	NDPI_LOG_INFO(ndpi_struct, "found DC CSUP ADBAS0 E\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_ADC_PEER);
	return;

      }

    }

  } else if(flow->directconnect_stage == 1) {
    if(packet->payload_packet_len >= 11) {
      /* did not see this pattern in any trace */
      if(memcmp(&packet->payload[0], "HSUP ADBAS0", 11) == 0
	  || memcmp(&packet->payload[0], "HSUP ADBASE", 11) == 0) {
	NDPI_LOG_INFO(ndpi_struct, "found DC HSUP ADBAS E in second packet\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_TYPE_HUB);
	return;
	/* did not see this pattern in any trace */
      } else if(memcmp(&packet->payload[0], "CSUP ADBAS0", 11) == 0 ||
		 memcmp(&packet->payload[0], "CSUP ADBASE", 11) == 0) {
	NDPI_LOG_INFO(ndpi_struct, "found DC HSUP ADBAS0 E in second packet\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_ADC_PEER);
	return;

      }
    }
    /* get client hello answer or server message */
    if(packet->payload_packet_len > 6) {
      if((packet->payload[0] == '$' || packet->payload[0] == '<')
	  && packet->payload[packet->payload_packet_len - 1] == '|') {
	NDPI_LOG_INFO(ndpi_struct, "found DC second\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_TYPE_HUB);
	return;
      } else {
	NDPI_LOG_DBG2(ndpi_struct, "second dc not detected\n");
      }

    }
  } else if(flow->directconnect_stage == 2) {
    /* get client hello answer or server message */
    if(packet->payload_packet_len > 6) {
      if(packet->payload[0] == '$' && packet->payload[packet->payload_packet_len - 1] == '|') {
	NDPI_LOG_INFO(ndpi_struct, "found DC between peers\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_TYPE_PEER);
	return;
      } else {
	NDPI_LOG_DBG2(ndpi_struct, "second dc between peers not detected\n");
      }
    }

  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

}

void ndpi_search_directconnect(struct ndpi_detection_module_struct
			       *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search DC\n");

  if(packet->tcp != NULL) {
    ndpi_search_directconnect_tcp(ndpi_struct, flow);
  }
}


void init_directconnect_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("DirectConnect", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DIRECTCONNECT,
				      ndpi_search_directconnect,
				      /* TODO: UDP?*/
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
