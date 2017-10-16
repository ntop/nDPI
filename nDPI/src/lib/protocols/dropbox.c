/*
 * dropbox.c
 *
 * Copyright (C) 2012-16 by ntop.org
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


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_DROPBOX

#define DB_LSP_PORT 17500


static void ndpi_int_dropbox_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					    u_int8_t due_to_correlation)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DROPBOX, NDPI_PROTOCOL_UNKNOWN);
}


static void ndpi_check_dropbox(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;  
  // const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;

  if(packet->udp != NULL) {
    u_int16_t dropbox_port = htons(DB_LSP_PORT);

    if((packet->udp->source == dropbox_port)
       && (packet->udp->dest == dropbox_port)) {
      if(payload_len > 2) {
	if(strncmp((const char *)packet->payload, "{\"host_int\"", 11) == 0) {
	  
	  NDPI_LOG(NDPI_PROTOCOL_DROPBOX, ndpi_struct, NDPI_LOG_DEBUG, "Found dropbox.\n");
	  ndpi_int_dropbox_add_connection(ndpi_struct, flow, 0);
	  return;
	}
      }
    }
  }
  
  NDPI_LOG(NDPI_PROTOCOL_DROPBOX, ndpi_struct, NDPI_LOG_DEBUG, "exclude dropbox.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DROPBOX);
}

void ndpi_search_dropbox(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_DROPBOX, ndpi_struct, NDPI_LOG_DEBUG, "dropbox detection...\n");

  /* skip marked packets */
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_DROPBOX) {
    if (packet->tcp_retransmission == 0) {
      ndpi_check_dropbox(ndpi_struct, flow);
    }
  }
}


void init_dropbox_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) 
{
  ndpi_set_bitmask_protocol_detection("DROPBOX", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DROPBOX,
				      ndpi_search_dropbox,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}



#endif
