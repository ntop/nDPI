/*
 * list.c
 *
 * Copyright (C) 2017-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_LISP

#include "ndpi_api.h"

#define LISP_PORT  4341
#define LISP_PORT1 4342

static void ndpi_int_lisp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					    u_int8_t due_to_correlation)
{

  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_LISP, NDPI_PROTOCOL_UNKNOWN);
}

static void ndpi_check_lisp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

  struct ndpi_packet_struct *packet = &flow->packet;  

  if(packet->udp != NULL) {

    u_int16_t lisp_port = htons(LISP_PORT);
    u_int16_t lisp_port1 = htons(LISP_PORT1);
    
    if(((packet->udp->source == lisp_port)
       && (packet->udp->dest == lisp_port)) || 
	((packet->udp->source == lisp_port1)
       && (packet->udp->dest == lisp_port1)) ) {
     
	  NDPI_LOG_INFO(ndpi_struct, "found lisp\n");
	  ndpi_int_lisp_add_connection(ndpi_struct, flow, 0);
	  return;

      }
    }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void ndpi_search_lisp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search lisp\n");

  /* skip marked packets */
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_LISP) {
 
      ndpi_check_lisp(ndpi_struct, flow);
   
  }
}


void init_lisp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) 
{
  ndpi_set_bitmask_protocol_detection("LISP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_LISP,
				      ndpi_search_lisp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

