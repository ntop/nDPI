/*
 * websocket.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WEBSOCKET

#include "ndpi_api.h"
#include "ndpi_private.h"

enum websocket_opcode
  {
    /*
     * CONTINUATION_FRAME is not relevant for the detection and leads to many false positives  
     CONTINUATION_FRAME = 0x00,
     FIN_CONTINUATION_FRAME = 0x80,
    */
    TEXT_FRAME = 0x01,
    FIN_TEXT_FRAME = 0x81,
    BINARY_FRAME = 0x02,
    FIN_BINARY_FRAME = 0x82,
    CONNECTION_CLOSE_FRAME = 0x08,
    FIN_CONNECTION_CLOSE_FRAME = 0x88,
    PING_FRAME = 0x09,
    FIN_PING_FRAME = 0x89,
    PONG_FRAME = 0x0A,
    FIN_PONG_FRAME = 0x8A
  };

static void set_websocket_detected(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  /* If no custom protocol has been detected */
  if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
    {
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WEBSOCKET, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    }
}

/*************************************************************************************************/

static void ndpi_check_websocket(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if (packet->payload_packet_len < sizeof(u_int16_t))
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

  u_int8_t websocket_payload_length = packet->payload[1] & 0x7F;
  u_int8_t websocket_masked = packet->payload[1] & 0x80;

  uint8_t hdr_size = (websocket_masked == 1) ? 6 : 2;

  if (packet->payload_packet_len != hdr_size + websocket_payload_length)
    {
      NDPI_LOG_DBG(ndpi_struct, "Invalid WEBSOCKET payload");
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

  if (packet->payload[0] == TEXT_FRAME ||  packet->payload[0] == FIN_TEXT_FRAME || 
      packet->payload[0] == BINARY_FRAME || packet->payload[0] == FIN_BINARY_FRAME || 
      packet->payload[0] == CONNECTION_CLOSE_FRAME || packet->payload[0] == FIN_CONNECTION_CLOSE_FRAME || 
      packet->payload[0] == PING_FRAME || packet->payload[0] == FIN_PING_FRAME || 
      packet->payload[0] == PONG_FRAME || packet->payload[0] == FIN_PONG_FRAME) {

    set_websocket_detected(ndpi_struct, flow);

  } else {
    NDPI_LOG_DBG(ndpi_struct, "Invalid WEBSOCKET payload");
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
}

static void ndpi_search_websocket(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  // Break after 6 packets.
  if (flow->packet_counter > 10)
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

  NDPI_LOG_DBG(ndpi_struct, "search WEBSOCKET\n");
  ndpi_check_websocket(ndpi_struct, flow);

  // Check also some HTTP headers indicating an upcoming WebSocket connection
  if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP &&
      flow->detected_protocol_stack[1] != NDPI_PROTOCOL_WEBSOCKET)
  {
    struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
    uint16_t i;

    NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);
    for (i = 0; i < packet->parsed_lines; i++) {
      if (LINE_STARTS(packet->line[i], "upgrade:") != 0 &&
          LINE_ENDS(packet->line[i], "websocket") != 0)
      {
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WEBSOCKET,
                                   NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
      } else if (LINE_STARTS(packet->line[i], "sec-websocket") != 0) {
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WEBSOCKET,
                                   NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
        if (ndpi_strncasestr((const char *)packet->line[i].ptr, "chisel",
                             packet->line[i].len) != NULL)
        {
          ndpi_set_risk(ndpi_struct, flow, NDPI_OBFUSCATED_TRAFFIC,
                        "Obfuscated SSH-in-HTTP-WebSocket traffic");
        }
      }
    }
    if (i == packet->parsed_lines)
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
  }

  return;
}

/* ********************************* */

void init_websocket_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("WEBSOCKET", ndpi_struct, *id, NDPI_PROTOCOL_WEBSOCKET,
                                     ndpi_search_websocket, NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                     SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
