/*
 * skinny.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SKINNY

#include "ndpi_api.h"


static void ndpi_int_skinny_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SKINNY, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_skinny(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;
  const char pattern_9_bytes[9] = { 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const char pattern_8_bytes[8] = { 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const char keypadmsg_8_bytes[8] = { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const char selectmsg_8_bytes[8] = { 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  NDPI_LOG_DBG(ndpi_struct, "search for SKINNY\n");

  if(packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG_DBG2(ndpi_struct, "calculating SKINNY over tcp\n");
    if (dport == 2000  && ((packet->payload_packet_len == 24 &&
			    memcmp(&packet->payload[0], keypadmsg_8_bytes, 8) == 0) 
			   || ((packet->payload_packet_len == 64) && memcmp(&packet->payload[0], pattern_8_bytes, 8) == 0))) {
      NDPI_LOG_INFO(ndpi_struct, "found skinny\n");
      ndpi_int_skinny_add_connection(ndpi_struct, flow);
    } else if (sport == 2000 && ((packet->payload_packet_len == 28 &&
				 memcmp(&packet->payload[0], selectmsg_8_bytes, 8) == 0 ) ||
	       (packet->payload_packet_len == 44 &&
		memcmp(&packet->payload[0], pattern_9_bytes, 9) == 0))) {
      NDPI_LOG_INFO(ndpi_struct, "found skinny\n");
      ndpi_int_skinny_add_connection(ndpi_struct, flow);
    }
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}


void init_skinny_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("CiscoSkinny", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SKINNY,
				      ndpi_search_skinny,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
