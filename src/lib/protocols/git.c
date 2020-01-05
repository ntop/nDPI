/*
 * git.c
 *
 * Copyright (C) 2012-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_GIT

#include <stdlib.h>
#include "ndpi_api.h"


#define GIT_PORT 9418

void ndpi_search_git(struct ndpi_detection_module_struct *ndpi_struct,
		     struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Git\n");

  if((packet->tcp != NULL) && (packet->payload_packet_len > 4)) {
    if((ntohs(packet->tcp->source) == GIT_PORT)
       || (ntohs(packet->tcp->dest) == GIT_PORT)) {
      const u_int8_t * pp = packet->payload;
      u_int16_t payload_len = packet->payload_packet_len;  
      u_int8_t found_git = 1;
      u_int16_t offset = 0;
      
      while((offset+4) < payload_len) {
	char len[5];
	u_int32_t git_pkt_len;

	memcpy(&len, &pp[offset], 4), len[4] = 0;
	git_pkt_len = atoi(len);

	if((payload_len < git_pkt_len) || (git_pkt_len == 0 /* Bad */)) {
	  found_git = 0;
	  break;
	} else
	  offset += git_pkt_len, payload_len -= git_pkt_len;      
      }

      if(found_git) {
	NDPI_LOG_INFO(ndpi_struct, "found Git\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_GIT, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
    }
  }
  
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


/* ***************************************************************** */

void init_git_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Git", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_GIT,
				      ndpi_search_git,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
