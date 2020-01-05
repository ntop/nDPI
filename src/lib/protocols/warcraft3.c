/*
 * warcraft3.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WARCRAFT3

#include "ndpi_api.h"

static void ndpi_int_warcraft3_add_connection(struct ndpi_detection_module_struct
					      *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WARCRAFT3, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_warcraft3(struct ndpi_detection_module_struct
			   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	
  u_int16_t l; /* 
		  Leave it as u_int32_t because otherwise 'u_int16_t temp' 
		  might overflood it and thus generate an infinite loop
	       */

  NDPI_LOG_DBG(ndpi_struct, "search WARCRAFT3\n");


  if (flow->packet_counter == 1 && packet->payload_packet_len == 1 && packet->payload[0] == 0x01) {
    NDPI_LOG_DBG2(ndpi_struct, "maybe warcraft3: packet_len == 1\n");
    return;
  } else if (packet->payload_packet_len >= 4 && (packet->payload[0] == 0xf7 || packet->payload[0] == 0xff)) {

    NDPI_LOG_DBG2(ndpi_struct, "packet_payload begins with 0xf7 or 0xff\n");

    l = packet->payload[2] + (packet->payload[3] << 8);	// similar to ntohs

    NDPI_LOG_DBG2(ndpi_struct, "l = %u \n", l);

    while (l <= (packet->payload_packet_len - 4)) {
      if (packet->payload[l] == 0xf7) {
	u_int16_t temp = (packet->payload[l + 2 + 1] << 8) + packet->payload[l + 2];
	NDPI_LOG_DBG2(ndpi_struct, "another f7 visited\n");

	if((temp <= 2) || (temp > 1500)) {
	  NDPI_LOG_DBG2(ndpi_struct, "break\n");
	  break;
	} else {
	  l += temp;
	  NDPI_LOG_DBG2(ndpi_struct, "l = %u \n", l);
	}
      } else {
	NDPI_LOG_DBG2(ndpi_struct, "break\n");
	break;
      }
    }

    if (l == packet->payload_packet_len) {
      NDPI_LOG_DBG2(ndpi_struct, "maybe WARCRAFT3 flow->packet_counter = %u \n",
	       flow->packet_counter);
      if (flow->packet_counter > 2) {
	NDPI_LOG_INFO(ndpi_struct, "found WARCRAFT3\n");
	ndpi_int_warcraft3_add_connection(ndpi_struct, flow);
	return;
      }
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_warcraft3_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Warcraft3", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_WARCRAFT3,
				      ndpi_search_warcraft3,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

