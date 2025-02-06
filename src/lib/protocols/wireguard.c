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
#include "ndpi_private.h"

/*
 * See https://www.wireguard.com/protocol/ for protocol reference.
 */

enum wg_message_type {
  WG_TYPE_HANDSHAKE_INITIATION = 1,
  WG_TYPE_HANDSHAKE_RESPONSE = 2,
  WG_TYPE_COOKIE_REPLY = 3,
  WG_TYPE_TRANSPORT_DATA = 4
};

static void ndpi_int_wireguard_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                              struct ndpi_flow_struct * const flow,
                                              u_int16_t app_protocol)
{
  if(ndpi_struct->cfg.wireguard_subclassification_by_ip &&
     ndpi_struct->proto_defaults[flow->guessed_protocol_id_by_ip].protoCategory == NDPI_PROTOCOL_CATEGORY_VPN) {
    ndpi_set_detected_protocol(ndpi_struct, flow, flow->guessed_protocol_id_by_ip, NDPI_PROTOCOL_WIREGUARD, NDPI_CONFIDENCE_DPI);
  } else if(app_protocol != NDPI_PROTOCOL_UNKNOWN) {
    ndpi_set_detected_protocol(ndpi_struct, flow, app_protocol, NDPI_PROTOCOL_WIREGUARD, NDPI_CONFIDENCE_DPI);
  } else {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WIREGUARD, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  }
}


static void ndpi_search_wireguard(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *payload = packet->payload;
  u_int8_t message_type = payload[0];

  NDPI_LOG_DBG(ndpi_struct, "search WireGuard\n");

  /*
   * First, try some easy ways to rule out the protocol.
   * The packet size and the reserved bytes in the header are good candidates.
   */

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
   * Below we make a deeper analysis; possibly inspecting multiple packets to
   * look for consistent sender/receiver index fields. We also exploit the fact
   * that handshake messages always have a fixed size.
   *
   * Stages 1-2 means we are processing a handshake sequence.
   * Stages 3-4 means we are processing a transport packet sequence.
   *
   * Message type can be one of the following:
   * 1) Handshake Initiation (148 bytes)
   * 2) Handshake Response (92 bytes)
   * 3) Cookie Reply (64 bytes)
   * 4) Transport Data (variable length, min 32 bytes)
   *
   *
   * TunnelBear VPN uses slightly different handshake packets: the format seems the same,
   * but the length is different (204/100). Not sure why and I don't know if it is some
   * kind of generic "obfuscation" attempt, used also by other apps. For the time being,
   * classify this kind of traffic as Wireguard/TunnelBear
   */
  if (message_type == WG_TYPE_HANDSHAKE_INITIATION &&
      (packet->payload_packet_len == 148 || packet->payload_packet_len == 204)) {
    u_int32_t sender_index = get_u_int32_t(payload, 4);
    /*
     * We always start a new detection stage on a handshake initiation.
     */
    flow->l4.udp.wireguard_stage = 1 + packet->packet_direction;
    flow->l4.udp.wireguard_peer_index[packet->packet_direction] = sender_index;

    if(flow->num_processed_pkts > 1) {
      /* This looks like a retransmission and probably this communication is blocked hence let's stop here */
      ndpi_int_wireguard_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
      return;
    } 
    /* need more packets before deciding */
  } else if (message_type == WG_TYPE_HANDSHAKE_RESPONSE &&
             (packet->payload_packet_len == 92 || packet->payload_packet_len == 100)) {
    if (flow->l4.udp.wireguard_stage == 2 - packet->packet_direction) {
      /*
       * This means we are probably processing a handshake response to a handshake
       * initiation that we've just processed, so we check if the receiver index
       * matches the index in the handshake initiation.
       */
      u_int32_t receiver_index = get_u_int32_t(payload, 8);

      if (receiver_index == flow->l4.udp.wireguard_peer_index[1 - packet->packet_direction]) {
        if(packet->payload_packet_len == 100)
          ndpi_int_wireguard_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TUNNELBEAR);
        else
          ndpi_int_wireguard_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
      } else {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      }
    }
    /* need more packets before deciding */
  } else if (message_type == WG_TYPE_COOKIE_REPLY && packet->payload_packet_len == 64) {
    /*
     * A cookie reply is sent as response to a handshake initiation when under load,
     * for DoS mitigation. If we have just seen a handshake initiation before
     * this cookie reply packet, we check if the receiver index in this packet
     * matches the sender index in that handshake initiation packet.
     */
    if (flow->l4.udp.wireguard_stage == 2 - packet->packet_direction) {
      u_int32_t receiver_index = get_u_int32_t(payload, 4);
      if (receiver_index == flow->l4.udp.wireguard_peer_index[1 - packet->packet_direction]) {
        ndpi_int_wireguard_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
      } else {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      }
    }
    /* need more packets before deciding */
  } else if (message_type == WG_TYPE_TRANSPORT_DATA) {
    /*
     * For detecting transport data packets, we save the peer
     * indices in both directions first. This requires at least one packet in each
     * direction (stages 3-4). The third packet that we process will be checked
     * against the appropriate index for a match (stage 5).
     */
    u_int32_t receiver_index = get_u_int32_t(payload, 4);

    /* We speculate this is wireguard, so let's remember it */
    flow->fast_callback_protocol_id = NDPI_PROTOCOL_WIREGUARD;
    
    if (flow->l4.udp.wireguard_stage == 0) {
      flow->l4.udp.wireguard_stage = 3 + packet->packet_direction;
      flow->l4.udp.wireguard_peer_index[packet->packet_direction] = receiver_index;
      /* need more packets before deciding */
    } else if (flow->l4.udp.wireguard_stage == 4 - packet->packet_direction) {
      flow->l4.udp.wireguard_peer_index[packet->packet_direction] = receiver_index;
      flow->l4.udp.wireguard_stage = 5;
      /* need more packets before deciding */
    } else if (flow->l4.udp.wireguard_stage == 5) {
      if (receiver_index == flow->l4.udp.wireguard_peer_index[packet->packet_direction]) {
        ndpi_int_wireguard_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
      } else {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      }
    }
    /* need more packets before deciding */
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}

void init_wireguard_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("WireGuard", ndpi_struct, *id,
				      NDPI_PROTOCOL_WIREGUARD,
				      ndpi_search_wireguard,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
