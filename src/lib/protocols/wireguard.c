/*
 * wireguard.c
 *
 * Copyright (C) 2019 - ntop.org
 * Copyright (C) 2019 - Yağmur Oymak
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WIREGUARD

#include "ndpi_api.h"

/*
 * TODO: Detection mechanism can be improved by taking the properties
 * of specific message types into account. For example:
 *  - Handshake messages have a fixed size.
 *  - Counter field is an integer that is incremented with each packet.
 *  - Receiver/sender index fields.
 * etc. (https://lists.zx2c4.com/pipermail/wireguard/2016-July/000185.html)
 * Exploiting these properties may reduce the probability of false positives;
 * with the tradeoff of requiring the inspection of multiple packets.
 *
 * Current approach identifies the protocol with a single packet and
 * does not yield false positives in any of the existing tests.
 */

/*
 * See https://www.wireguard.com/protocol/ for protocol reference.
 */
void ndpi_search_wireguard(struct ndpi_detection_module_struct
			   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  const u_int8_t *payload = packet->payload;
  /*
   * The first byte of the payload is the message type.
   */
  u_int8_t message_type = payload[0];

  NDPI_LOG_DBG(ndpi_struct, "search WireGuard\n");
  /*
   * A transport packet contains at minimum the following fields:
   *  u8 message_type
   *  u8 reserved_zero[3]
   *  u32 receiver_index
   *  u64 counter
   *  u8 encrypted_encapsulated_packet[]
   * In the case of a keepalive message, the encapsulated packet will have
   * zero length, but will still have a 16 byte poly1305 authentication tag.
   * Thus, packet->payload will be at least 32 bytes in size.
   * Note that handshake packets have a slightly different structure, but they are larger.
   */
  if (packet->payload_packet_len < 32) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  /*
   * The next three bytes after the message type are reserved and set to zero.
   */
  if (payload[1] != 0 || payload[2] != 0 || payload[3] != 0) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  /*
   * Message type can have one of the following values:
   * 1) Handshake Initiation
   * 2) Handshake Response
   * 3) Cookie Reply
   * 4) Transport Data
   */
  if (message_type == 0 || message_type > 4) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WIREGUARD, NDPI_PROTOCOL_UNKNOWN);
  return;
}

void init_wireguard_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("WireGuard", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_WIREGUARD,
				      ndpi_search_wireguard,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

