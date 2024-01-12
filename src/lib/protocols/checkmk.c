/*
 * checkmk.c
 *
 * Copyright (C) 2011-22 - ntop.org
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
 *
 */
#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CHECKMK

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_checkmk_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CHECKMK, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}


static void ndpi_search_checkmk(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Checkmk\n");

  if (packet->payload_packet_len >= 15) {

    if(packet->payload_packet_len > 128) {
      /*
	When we transfer a large data chunk, unless we have observed
	the initial connection, we need to discard these packets
	as they are not an indication that this flow is not AFP
      */
      if(flow->packet_counter > 6)
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    /*
     * this will detect the OpenSession command of the Data Stream Interface (DSI) protocol
     * which is exclusively used by the Apple Filing Protocol (AFP) on TCP/IP networks
     */
    if (packet->payload_packet_len < 100
        && memcmp(packet->payload, "<<<check_mk>>>", 14) == 0) {

      NDPI_LOG_DBG(ndpi_struct, "Check_MK: Flow detected.\n");
      ndpi_int_checkmk_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_LOG_DBG(ndpi_struct, "Check_MK excluded.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_CHECKMK);
}


void init_checkmk_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			    u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("CHECKMK", ndpi_struct, *id,
				      NDPI_PROTOCOL_CHECKMK,
				      ndpi_search_checkmk,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
