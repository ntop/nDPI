/*
 * ajp.c
 *
 * Copyright (C) 2018 by Leonn Paiva <leonn.paiva@gmail.com>
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
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_AJP

#include "ndpi_api.h"

enum ajp_direction {
  AJP_SERVER_TO_CONTAINER = 0x1234,
  AJP_CONTAINER_TO_SERVER = 0x4142
};

enum ajp_packet_type {
  AJP_UNKNOWN = 0,

   /* packet types */
  AJP_FORWARD_REQUEST = 2,
  AJP_SEND_BODY_CHUNK = 3,
  AJP_SEND_HEADERS = 4,
  AJP_END_RESPONSE = 5,
  AJP_GET_BODY_CHUNK = 6,
  AJP_SHUTDOWN = 7,
  AJP_PING = 8,
  AJP_CPONG = 9,
  AJP_CPING = 10,
  AJP_BODY = 11
};

PACK_ON
struct ajp_header {
  uint16_t magic;
  uint16_t len;
  uint8_t code;
} PACK_OFF;

static void set_ajp_detected(struct ndpi_detection_module_struct *ndpi_struct,
           struct ndpi_flow_struct *flow) {

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
    ndpi_search_tcp_or_udp(ndpi_struct, flow);

    /* If no custom protocol has been detected */
    /* if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) */
      ndpi_int_reset_protocol(flow);
      ndpi_set_detected_protocol(ndpi_struct, flow, flow->guessed_host_protocol_id, NDPI_PROTOCOL_AJP);
  }
}


/*************************************************************************************************/

static void ndpi_check_ajp(struct ndpi_detection_module_struct *ndpi_struct,
			   struct ndpi_flow_struct *flow) {
  struct ajp_header ajp_hdr;
  struct ndpi_packet_struct *packet = &flow->packet;

  if (packet->payload_packet_len < sizeof(ajp_hdr)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  memcpy(&ajp_hdr, packet->payload, sizeof(struct ajp_header));
  
  ajp_hdr.magic = ntohs(ajp_hdr.magic);
  ajp_hdr.len = ntohs(ajp_hdr.len);

  if (ajp_hdr.len > 0 && ajp_hdr.magic == AJP_SERVER_TO_CONTAINER) {
    if (ajp_hdr.code == AJP_FORWARD_REQUEST || ajp_hdr.code == AJP_SHUTDOWN
        || ajp_hdr.code == AJP_PING || ajp_hdr.code == AJP_CPING) {

      set_ajp_detected(ndpi_struct, flow);

    } else {
      NDPI_LOG_DBG(ndpi_struct, "Invalid AJP request type");
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
  } else if (ajp_hdr.len > 0 && ajp_hdr.magic == AJP_CONTAINER_TO_SERVER) {
    if (ajp_hdr.code == AJP_SEND_BODY_CHUNK || ajp_hdr.code == AJP_SEND_HEADERS
        || ajp_hdr.code == AJP_END_RESPONSE || ajp_hdr.code == AJP_GET_BODY_CHUNK
        || ajp_hdr.code == AJP_CPONG) {

      set_ajp_detected(ndpi_struct, flow);

    } else {
      NDPI_LOG_DBG(ndpi_struct, "Invalid AJP response type");
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
  } else {
    NDPI_LOG_DBG(ndpi_struct,"Invalid AJP packet\n");
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}

void ndpi_search_ajp(struct ndpi_detection_module_struct *ndpi_struct,
 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  // Break after 20 packets.
  if(flow->packet_counter > 20) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
    return;
  }

  NDPI_LOG_DBG(ndpi_struct, "search AJP\n");
  ndpi_check_ajp(ndpi_struct, flow);

  return;
}

/* ********************************* */


void init_ajp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
  u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("AJP", ndpi_struct, detection_bitmask,
    *id, NDPI_PROTOCOL_AJP, ndpi_search_ajp,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
