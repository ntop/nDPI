/*
 * raft.c
 *
 * Copyright (C) 2024 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RAFT
#include "ndpi_api.h"
#include "ndpi_private.h"

PACK_ON
struct raft_header {
  uint64_t msg_type;
  uint64_t msg_length;
} PACK_OFF;

enum raft_header_type {
  RAFT_IO_APPEND_ENTRIES = 1,
  RAFT_IO_APPEND_ENTRIES_RESULT,
  RAFT_IO_REQUEST_VOTE,
  RAFT_IO_REQUEST_VOTE_RESULT,
  RAFT_IO_INSTALL_SNAPSHOT,
  RAFT_IO_TIMEOUT_NOW
};

static void ndpi_int_raft_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                         struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found raft\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_RAFT,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_raft(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  struct raft_header const * const raft_header = (struct raft_header *)packet->payload;

  NDPI_LOG_DBG(ndpi_struct, "search raft\n");

  if (packet->payload_packet_len < sizeof(*raft_header))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  uint64_t msg_type = le64toh(raft_header->msg_type);
  switch (msg_type)
  {
    case RAFT_IO_APPEND_ENTRIES:
    case RAFT_IO_APPEND_ENTRIES_RESULT:
    case RAFT_IO_REQUEST_VOTE:
    case RAFT_IO_REQUEST_VOTE_RESULT:
    case RAFT_IO_INSTALL_SNAPSHOT:
    case RAFT_IO_TIMEOUT_NOW:
      break;

    default:
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
  }

  uint64_t msg_length = le64toh(raft_header->msg_length);
  if (msg_length == packet->payload_packet_len - sizeof(*raft_header))
  {
    ndpi_int_raft_add_connection(ndpi_struct, flow);
    return;
  }

  if (flow->packet_counter < 3)
  {
    return;
  }

  ndpi_int_raft_add_connection(ndpi_struct, flow);
}

void init_raft_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                         u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Raft", ndpi_struct, *id,
                                      NDPI_PROTOCOL_RAFT,
                                      ndpi_search_raft,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

