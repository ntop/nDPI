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


#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UBNTAC2

#include "ndpi_api.h"

static void ndpi_int_ubntac2_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_UBNTAC2, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_ubntac2(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search ubntac2\n");
  NDPI_LOG_DBG2(ndpi_struct, "UBNTAC2 detection... plen:%i %i:%i\n", packet->payload_packet_len, ntohs(packet->udp->source), ntohs(packet->udp->dest));

  if(packet->udp) {
    if(packet->payload_packet_len >= 135 &&
       (packet->udp->source == htons(10001) || packet->udp->dest == htons(10001))) {
      int found = 0;
      
      if(memcmp(&(packet->payload[36]), "UBNT", 4) == 0) {
	found = 36+5;
      } else if(memcmp(&(packet->payload[49]), "ubnt", 4) == 0) {
	found = 49+5;
      }

      if(found) {
	found += packet->payload[found+1] + 4; /* Skip model name */
	found++; /* Skip len */
	
	if(found < packet->payload_packet_len) {
	  char version[256];
	  int i, j, len;
	  
	  for(i=found, j=0; (i < packet->payload_packet_len)
		&& (i < (sizeof(version)-1))
		&& (packet->payload[i] != 0); i++)
	    version[j++] = packet->payload[i];
	  
	  version[j] = '\0';

	  len = ndpi_min(sizeof(flow->protos.ubntac2.version)-1, j);
	  strncpy(flow->protos.ubntac2.version, (const char *)version, len);
	  flow->protos.ubntac2.version[len] = '\0';
	}
	
	NDPI_LOG_INFO(ndpi_struct, "UBNT AirControl 2 request\n");
	
	ndpi_int_ubntac2_add_connection(ndpi_struct, flow);
      }
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
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
