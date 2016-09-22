/*
 * ubntac2.c
 *
 * Copyright (C) 2015 Thomas Fjellstrom
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

#ifdef NDPI_PROTOCOL_UBNTAC2

static void ndpi_int_ubntac2_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_UBNTAC2, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_ubntac2(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_UBNTAC2, ndpi_struct, NDPI_LOG_TRACE, "UBNTAC2 detection... plen:%i %i:%i\n", packet->payload_packet_len, ntohs(packet->udp->source), ntohs(packet->udp->dest));

  if(packet->udp) {
    if(packet->payload_packet_len >= 135 &&
       (packet->udp->source == htons(10001) || packet->udp->dest == htons(10001)) &&
       memcmp(&(packet->payload[36]), "UBNT", 4) == 0) {
      
      NDPI_LOG(NDPI_PROTOCOL_UBNTAC2, ndpi_struct, NDPI_LOG_DEBUG, "UBNT AirControl 2 request\n");
      
      ndpi_int_ubntac2_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_UBNTAC2);
}


void init_ubntac2_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("UBNTAC2", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_UBNTAC2,
				      ndpi_search_ubntac2,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

#endif
