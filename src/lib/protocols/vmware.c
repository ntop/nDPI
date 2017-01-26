/*
 * vmware.c
 *
 * Copyright (C) 2016 - ntop.org
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
#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_VMWARE


void ndpi_search_vmware(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  /* Check whether this is an VMWARE flow */
  if(packet->udp != NULL){
    if((packet->payload_packet_len == 66) &&
       (ntohs(packet->udp->dest) == 902) &&
       ((packet->payload[0] & 0xFF) == 0xA4)){
      
      NDPI_LOG(NDPI_PROTOCOL_VMWARE, ndpi_struct, NDPI_LOG_DEBUG, "Found vmware.\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_VMWARE, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
  }
  NDPI_LOG(NDPI_PROTOCOL_VMWARE, ndpi_struct, NDPI_LOG_DEBUG, "exclude vmware.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_VMWARE);
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

#endif
