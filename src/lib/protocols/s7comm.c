/*
 * s7comm.c
 *
 * Copyright (C) 2023 - ntop.org
 * Copyright (C) 2023 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_S7COMM

#include "ndpi_api.h"
#include "ndpi_private.h"

#define TPKT_PORT               102
#define S7COMM_MAGIC_BYTE       0x32
#define S7COMM_PLUS_MAGIC_BYTE  0x72

static void ndpi_search_s7comm(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search S7comm\n");

  if (tpkt_verify_hdr(packet) && (packet->payload_packet_len > 17) &&
      ((packet->tcp->source == htons(TPKT_PORT)) ||
       (packet->tcp->dest == htons(TPKT_PORT))))
  {
    if (packet->payload[7] == S7COMM_PLUS_MAGIC_BYTE) {
      const u_int16_t trail_byte_offset = packet->payload_packet_len - 4;
      if (packet->payload[trail_byte_offset] == S7COMM_PLUS_MAGIC_BYTE) {
        NDPI_LOG_INFO(ndpi_struct, "found S7CommPlus\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_S7COMM_PLUS, 
                                   NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
        return;
      } 
    } else if (packet->payload[7] == S7COMM_MAGIC_BYTE) {
      if (((packet->payload[8] <= 0x03) || (packet->payload[8] == 0x07)) &&
          (get_u_int16_t(packet->payload, 9) == 0))
      {
        NDPI_LOG_INFO(ndpi_struct, "found S7Comm\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_S7COMM, 
                                   NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
        return;
      }
    }
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_s7comm_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("S7Comm", ndpi_struct, *id,
                                      NDPI_PROTOCOL_S7COMM,
                                      ndpi_search_s7comm,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
