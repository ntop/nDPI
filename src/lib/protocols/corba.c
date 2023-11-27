/*
 * corba.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CORBA

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_corba_add_connection(struct ndpi_detection_module_struct
                                          *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Corba\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CORBA, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}
static void ndpi_search_corba(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search for Corba\n");

  if (packet->tcp != NULL && packet->payload_packet_len >= 24) {
    /* General Inter-ORB Protocol -> GIOP
     * Zipped Inter-ORB Protocol  -> ZIOP */
    if ((memcmp(packet->payload, "GIOP", 4) == 0) ||
        (memcmp(packet->payload, "ZIOP", 4) == 0))
    {
      ndpi_int_corba_add_connection(ndpi_struct, flow);
      return;
    }
  } 
  else if (packet->udp != NULL && packet->payload_packet_len > 32) {
    /* Unreliable Multicast Inter-ORB Protocol -> MIOP */
    if (memcmp(packet->payload, "MIOP", 4) == 0) {
      ndpi_int_corba_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_corba_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Corba", ndpi_struct, *id,
				      NDPI_PROTOCOL_CORBA,
				      ndpi_search_corba,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
