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
#include "ndpi_private.h"

static void ndpi_int_rtmp_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RTMP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_check_rtmp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  
  /* Look for the handshake, which is only at the beginning of the flow:
      C->S: 0x03 + 1536 bytes
      S->C: 0X03 + something...; we don't really check the length of the burst sent by the server, to avoid to save further state
     See: https://en.wikipedia.org/w/index.php?title=Real-Time_Messaging_Protocol&section=12#Handshake */

  if(!ndpi_seen_flow_beginning(flow)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /* TODO: should we check somehow for mid-flows? */

  if(flow->l4.tcp.rtmp_stage == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "RTMP stage 0: \n");
     
    if(packet->payload[0] == 0x03) {
      flow->l4.tcp.rtmp_stage = packet->packet_direction + 1;
      flow->l4.tcp.rtmp_client_buffer_len = packet->payload_packet_len;
      return;
    }
  } else {
    NDPI_LOG_DBG2(ndpi_struct, "RTMP stage %u (client already sent %d bytes)\n",
                  flow->l4.tcp.rtmp_stage, flow->l4.tcp.rtmp_client_buffer_len);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if(flow->l4.tcp.rtmp_stage - packet->packet_direction == 1) {
      /* From the same direction */
      flow->l4.tcp.rtmp_client_buffer_len += packet->payload_packet_len;
      if(flow->l4.tcp.rtmp_client_buffer_len <= 1537)
        return;
    }

    /* This is a packet in another direction */
    if(packet->payload[0] == 0x03 && flow->l4.tcp.rtmp_client_buffer_len == 1537) {
      NDPI_LOG_INFO(ndpi_struct, "found RTMP\n");
      ndpi_int_rtmp_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

static void ndpi_search_rtmp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_DBG(ndpi_struct, "search RTMP\n");

  ndpi_check_rtmp(ndpi_struct, flow);
}


void init_rtmp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("RTMP", ndpi_struct, *id,
				      NDPI_PROTOCOL_RTMP,
				      ndpi_search_rtmp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

