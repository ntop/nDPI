/*
 * stealthnet.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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

#ifdef NDPI_PROTOCOL_STEALTHNET


static void ndpi_int_stealthnet_add_connection(struct ndpi_detection_module_struct
					       *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_STEALTHNET, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_stealthnet(struct ndpi_detection_module_struct
			    *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	

  //  struct ndpi_id_struct *src = flow->src;
  //  struct ndpi_id_struct *dst = flow->dst;


  if (packet->payload_packet_len > 40
      && memcmp(packet->payload, "LARS REGENSBURGER'S FILE SHARING PROTOCOL", 41) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_STEALTHNET, ndpi_struct, NDPI_LOG_DEBUG, "found stealthnet\n");
    ndpi_int_stealthnet_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_LOG(NDPI_PROTOCOL_STEALTHNET, ndpi_struct, NDPI_LOG_DEBUG, "exclude stealthnet.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_STEALTHNET);

}


void init_stealthnet_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{

  ndpi_set_bitmask_protocol_detection("Stealthnet", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_STEALTHNET,
				      ndpi_search_stealthnet,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
