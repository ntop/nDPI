/*
 * rtmp.c
 *
 * Copyright (C) 2020 - ntop.org
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
 * 
 * The signature is based on the Libprotoident library.
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RTMP

#include "ndpi_api.h"

static void ndpi_int_rtmp_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RTMP, NDPI_PROTOCOL_UNKNOWN);
}

static void ndpi_check_rtmp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;  
  u_int32_t payload_len = packet->payload_packet_len;
  
  /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  
  /* Check if we so far detected the protocol in the request or not. */
  if(flow->rtmp_stage == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "RTMP stage 0: \n");
     
    if ((payload_len >= 4) && ((packet->payload[0] == 0x03) || (packet->payload[0] == 0x06))) {
      NDPI_LOG_DBG2(ndpi_struct, "Possible RTMP request detected, we will look further for the response\n");
       
      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->rtmp_stage = packet->packet_direction + 1;
    } else
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  } else {
    NDPI_LOG_DBG2(ndpi_struct, "RTMP stage %u: \n", flow->rtmp_stage);
    
    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if ((flow->rtmp_stage - packet->packet_direction) == 1) {
      return;
    }
    
    /* This is a packet in another direction. Check if we find the proper response. */
    if ((payload_len >= 4) && ((packet->payload[0] == 0x03) || (packet->payload[0] == 0x06) || (packet->payload[0] == 0x08) || (packet->payload[0] == 0x09) || (packet->payload[0] == 0x0a))) {
      NDPI_LOG_INFO(ndpi_struct, "found RTMP\n");
      ndpi_int_rtmp_add_connection(ndpi_struct, flow);
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to RTMP, resetting the stage to 0\n");
      flow->rtmp_stage = 0;
    }
  }
}

void ndpi_search_rtmp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search RTMP\n");

  /* skip marked packets */
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_RTMP) {
    if (packet->tcp_retransmission == 0) {
      ndpi_check_rtmp(ndpi_struct, flow);
    }
  }
}


void init_rtmp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("RTMP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_RTMP,
				      ndpi_search_rtmp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

