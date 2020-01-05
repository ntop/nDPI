/*
 * vmware.c
 *
 * Copyright (C) 2016-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_VMWARE

#include "ndpi_api.h"

void ndpi_search_vmware(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search vmware\n");
  /* Check whether this is an VMWARE flow */
  if(packet->udp != NULL){
    if((packet->payload_packet_len == 66) &&
       (ntohs(packet->udp->dest) == 902) &&
       ((packet->payload[0] & 0xFF) == 0xA4)){
      
      NDPI_LOG_INFO(ndpi_struct, "found vmware\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_VMWARE, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
  }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_vmware_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("VMWARE", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_VMWARE,
				      ndpi_search_vmware,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  
  *id += 1;
}
