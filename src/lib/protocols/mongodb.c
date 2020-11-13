/*
 * mongodb.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MONGODB

#include "ndpi_api.h"

enum mongo_opcodes
{
    OP_REPLY = 1,
    OP_UPDATE = 2001,
    OP_INSERT = 2002,
    RESERVED = 2003,
    OP_QUERY = 2004,
    OP_GET_MORE = 2005,
    OP_DELETE = 2006,
    OP_KILL_CURSORS = 2007,
    OP_MSG = 2013
};

struct mongo_message_header
{
    uint32_t message_length;
    uint32_t request_id;
    uint32_t response_to;
    enum mongo_opcodes op_code;
};

static void set_mongodb_detected(struct ndpi_detection_module_struct *ndpi_struct,
           struct ndpi_flow_struct *flow) {

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
    ndpi_search_tcp_or_udp(ndpi_struct, flow);

    /* If no custom protocol has been detected */
    /* if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) */
      ndpi_int_reset_protocol(flow);
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MONGODB, flow->guessed_host_protocol_id);
  }
}


/*************************************************************************************************/

static void ndpi_check_mongodb(struct ndpi_detection_module_struct *ndpi_struct,
			   struct ndpi_flow_struct *flow) {
  struct mongo_message_header mongodb_hdr;
  struct ndpi_packet_struct *packet = &flow->packet;

  if (packet->payload_packet_len <= sizeof(mongodb_hdr)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  memcpy(&mongodb_hdr, packet->payload, sizeof(struct mongo_message_header));

  mongodb_hdr.message_length = ntohs(mongodb_hdr.message_length);

  if (mongodb_hdr.message_length < 4) {
    NDPI_LOG_DBG(ndpi_struct, "Invalid MONGODB length");
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  switch(mongodb_hdr.op_code) {
    case OP_REPLY:
    case OP_UPDATE:
    case OP_INSERT:
    case RESERVED:
    case OP_QUERY:
    case OP_GET_MORE:
    case OP_DELETE:
    case OP_KILL_CURSORS:
    case OP_MSG:
      set_mongodb_detected(ndpi_struct, flow);
      break;
    default:
      NDPI_LOG_DBG(ndpi_struct, "Invalid MONGODB length");
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      break;
  }
}

void ndpi_search_mongodb(struct ndpi_detection_module_struct *ndpi_struct,
 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  // Break after 6 packets.
  if(flow->packet_counter > 6) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
    return;
  }

  NDPI_LOG_DBG(ndpi_struct, "search MongoDB\n");
  ndpi_check_mongodb(ndpi_struct, flow);

  return;
}

/* ********************************* */


void init_mongodb_dissector(struct ndpi_detection_module_struct *ndpi_struct,
  u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("MongoDB", ndpi_struct, detection_bitmask,
    *id, NDPI_PROTOCOL_MONGODB, ndpi_search_mongodb,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
