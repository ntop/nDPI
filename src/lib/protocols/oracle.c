/*
 * oracle.c
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


#ifdef NDPI_PROTOCOL_ORACLE
static void ndpi_int_oracle_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_ORACLE, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_oracle(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG(NDPI_PROTOCOL_ORACLE, ndpi_struct, NDPI_LOG_DEBUG, "search for ORACLE.\n");

  if(packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG(NDPI_PROTOCOL_ORACLE, ndpi_struct, NDPI_LOG_DEBUG, "calculating ORACLE over tcp.\n");
    /* Oracle Database 9g,10g,11g */
    if ((dport == 1521 || sport == 1521)
	&&  (((packet->payload[0] == 0x07) && (packet->payload[1] == 0xff) && (packet->payload[2] == 0x00))
	     || ((packet->payload_packet_len >= 232) && ((packet->payload[0] == 0x00) || (packet->payload[0] == 0x01)) 
	     && (packet->payload[1] != 0x00)
	     && (packet->payload[2] == 0x00)
		 && (packet->payload[3] == 0x00)))) {
      NDPI_LOG(NDPI_PROTOCOL_ORACLE, ndpi_struct, NDPI_LOG_DEBUG, "found oracle.\n");
      ndpi_int_oracle_add_connection(ndpi_struct, flow);
    } else if (packet->payload_packet_len == 213 && packet->payload[0] == 0x00 &&
               packet->payload[1] == 0xd5 && packet->payload[2] == 0x00 &&
               packet->payload[3] == 0x00 ) {
      NDPI_LOG(NDPI_PROTOCOL_ORACLE, ndpi_struct, NDPI_LOG_DEBUG, "found oracle.\n");
      ndpi_int_oracle_add_connection(ndpi_struct, flow);
    }
  } else {
    NDPI_LOG(NDPI_PROTOCOL_ORACLE, ndpi_struct, NDPI_LOG_DEBUG, "exclude ORACLE.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_ORACLE);
  }
}
#endif
