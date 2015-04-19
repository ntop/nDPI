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


#include "ndpi_api.h"


#ifdef NDPI_PROTOCOL_SKINNY
static void ndpi_int_skinny_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKINNY, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_skinny(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;
  const char pattern_9_bytes[9] = { 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const char pattern_8_bytes[8] = { 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const char keypadmsg_8_bytes[8] = { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const char selectmsg_8_bytes[8] = { 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  NDPI_LOG(NDPI_PROTOCOL_SKINNY, ndpi_struct, NDPI_LOG_DEBUG, "search for SKINNY.\n");

  if(packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG(NDPI_PROTOCOL_SKINNY, ndpi_struct, NDPI_LOG_DEBUG, "calculating SKINNY over tcp.\n");
    if (dport == 2000  && ((packet->payload_packet_len == 24 &&
			    memcmp(&packet->payload[0], keypadmsg_8_bytes, 8) == 0) 
			   || ((packet->payload_packet_len == 64) && memcmp(&packet->payload[0], pattern_8_bytes, 8) == 0))) {
      NDPI_LOG(NDPI_PROTOCOL_SKINNY, ndpi_struct, NDPI_LOG_DEBUG, "found skinny.\n");
      ndpi_int_skinny_add_connection(ndpi_struct, flow);
    } else if (sport == 2000 && ((packet->payload_packet_len == 28 &&
				 memcmp(&packet->payload[0], selectmsg_8_bytes, 8) == 0 ) ||
	       (packet->payload_packet_len == 44 &&
		memcmp(&packet->payload[0], pattern_9_bytes, 9) == 0))) {
      NDPI_LOG(NDPI_PROTOCOL_SKINNY, ndpi_struct, NDPI_LOG_DEBUG, "found skinny.\n");
      ndpi_int_skinny_add_connection(ndpi_struct, flow);
    }
  } else {
    NDPI_LOG(NDPI_PROTOCOL_SKINNY, ndpi_struct, NDPI_LOG_DEBUG, "exclude SKINNY.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SKINNY);
  }
}
#endif
