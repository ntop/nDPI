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

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ORACLE

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_oracle_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ORACLE, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_oracle(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG_DBG(ndpi_struct, "search ORACLE\n");

  /* For the time being, check only on default port since the logic is quite weak */
  sport = ntohs(packet->tcp->source);
  dport = ntohs(packet->tcp->dest);

  /* Check for Connect Request */
  if((dport == 1521 || sport == 1521) &&
     packet->payload_packet_len >= 8 &&
     ntohs(get_u_int16_t(packet->payload, 0)) == packet->payload_packet_len &&
     packet->payload[2] == 0x00 && packet->payload[3] == 0x00 && /* Packet Checksum */
     packet->payload[4] == 0x01 && /* Connect */
     packet->payload[5] == 0x00 && /* Reserved */
     packet->payload[6] == 0x00 && packet->payload[7] == 0x00 /* Header Checksum */) {
    NDPI_LOG_INFO(ndpi_struct, "found oracle\n");
    ndpi_int_oracle_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_oracle_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Oracle", ndpi_struct, *id,
				      NDPI_PROTOCOL_ORACLE,
				      ndpi_search_oracle,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
