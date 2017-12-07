/*
 * hep.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
 * Copyright (C) 2011-15 - QXIP BV
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


#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_HEP

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HEP

#include "ndpi_api.h"


static void ndpi_int_hep_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HEP, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_hep(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;

    NDPI_LOG_DBG(ndpi_struct, "searching HEP\n");
    if (payload_len > 10) {
	    if (memcmp(packet_payload, "HEP3", 4) == 0) {
	      NDPI_LOG_INFO(ndpi_struct, "found HEP3\n");
	      ndpi_int_hep_add_connection(ndpi_struct, flow);
	      return;
	    } 
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_hep_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("HEP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_HEP,
				      ndpi_search_hep,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
