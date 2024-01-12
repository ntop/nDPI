/*
 * kcp.c
 *
 * Copyright (C) 2024 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_KCP

#include "ndpi_api.h"
#include "ndpi_private.h"

PACK_ON
struct kcp_header {
  uint32_t conversation_id;
  uint8_t command;
  uint8_t fragment_count;
  uint16_t window_size;
  uint32_t timestamp;
  uint32_t serial_number;
  uint32_t unacknowledged_serial_number;
  uint32_t length;
  uint8_t data[0];
} PACK_OFF;

enum kcp_commands {
  IKCP_CMD_PUSH = 81,
  IKCP_CMD_ACK  = 82,
  IKCP_CMD_WASK = 83,
  IKCP_CMD_WINS = 84
};

static void ndpi_int_kcp_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                        struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found kcp\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_KCP,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_kcp(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  struct kcp_header const * const kcp_header = (struct kcp_header *)packet->payload;

  NDPI_LOG_INFO(ndpi_struct, "search kcp\n");

  if (packet->payload_packet_len < sizeof(*kcp_header))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  switch (kcp_header->command)
  {
    case IKCP_CMD_PUSH:
    case IKCP_CMD_ACK:
    case IKCP_CMD_WASK:
    case IKCP_CMD_WINS:
      break;
    default:
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
  }

  uint32_t const kcp_pdu_length = le32toh(kcp_header->length);
  if (kcp_pdu_length + sizeof(*kcp_header) != packet->payload_packet_len)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_kcp_add_connection(ndpi_struct, flow);
}

void init_kcp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                        u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("KCP", ndpi_struct, *id,
    NDPI_PROTOCOL_KCP,
    ndpi_search_kcp,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );

  *id += 1;
}
