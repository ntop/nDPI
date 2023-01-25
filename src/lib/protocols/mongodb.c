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

/* https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/ */

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
  uint32_t op_code; /* enum mongo_opcodes */
};

static void set_mongodb_detected(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MONGODB, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  }
}


/*************************************************************************************************/

static void ndpi_check_mongodb(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct mongo_message_header mongodb_hdr;
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  uint32_t responseFlags;

  if (packet->payload_packet_len <= sizeof(mongodb_hdr)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  memcpy(&mongodb_hdr, packet->payload, sizeof(struct mongo_message_header));

  /* All MongoDB numbers are in host byte order */
  // mongodb_hdr.message_length = ntohl(mongodb_hdr.message_length);

  if((le32toh(mongodb_hdr.message_length) < 4)
     || (le32toh(mongodb_hdr.message_length) > 1000000) /* Used to avoid false positives */
     ) {
    NDPI_LOG_DBG(ndpi_struct, "Invalid MONGODB length");
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  switch(le32toh(mongodb_hdr.op_code)) {
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
  case OP_REPLY:
    /* struct {
         MsgHeader header;         // standard message header
         int32     responseFlags;  // bit vector - see details below
         int64     cursorID;       // cursor id if client needs to do get more's
         int32     startingFrom;   // where in the cursor this reply is starting
         int32     numberReturned; // number of documents in the reply
         document* documents;      // documents
       }
    */
    if(packet->payload_packet_len > sizeof(mongodb_hdr) + 20) {
      responseFlags = le32toh(*(uint32_t *)(packet->payload + sizeof(mongodb_hdr)));
      if((responseFlags & 0xFFFFFFF0) == 0)
        set_mongodb_detected(ndpi_struct, flow);
    }
    break;

  default:
    NDPI_LOG_DBG(ndpi_struct, "Invalid MONGODB length");
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    break;
  }
}

static void ndpi_search_mongodb(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow)
{
  // Break after 6 packets.
  if(flow->packet_counter > 6) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  NDPI_LOG_DBG(ndpi_struct, "search MongoDB\n");
  ndpi_check_mongodb(ndpi_struct, flow);

  return;
}

/* ********************************* */


void init_mongodb_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			    u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("MongoDB", ndpi_struct,
				      *id, NDPI_PROTOCOL_MONGODB, ndpi_search_mongodb,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
