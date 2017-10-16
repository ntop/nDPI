/*
 * smb.c
 *
 * Copyright (C) 2016 - ntop.org
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
#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_SMB


void ndpi_search_smb_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  /* Check connection over TCP */
  if(packet->tcp) {
    NDPI_LOG(NDPI_PROTOCOL_SMB, ndpi_struct, NDPI_LOG_DEBUG, "search SMB.\n");
    
    if(packet->tcp->dest == htons(445)
       && packet->payload_packet_len > (32 + 4 + 4)
       && (packet->payload_packet_len - 4) == ntohl(get_u_int32_t(packet->payload, 0))
       && get_u_int32_t(packet->payload, 4) == htonl(0xff534d42)) {
      
      NDPI_LOG(NDPI_PROTOCOL_SMB, ndpi_struct, NDPI_LOG_DEBUG, "found SMB.\n");

      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SMB, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
  }

  NDPI_LOG(NDPI_PROTOCOL_SMB, ndpi_struct, NDPI_LOG_DEBUG, "exclude SMB.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SMB);
}


void init_smb_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("SMB", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SMB,
				      ndpi_search_smb_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
