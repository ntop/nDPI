/*
 * netmotion.c
 *
 * NetMotion Mobility (Mobility XE) - Internet Mobility Protocol (IMP)
 *
 * Copyright (C) 2026 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NETMOTION

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * NetMotion Mobility clients tunnel to the Mobility server over the Internet
 * Mobility Protocol (IMP), by default UDP/5008. IMP is connection-oriented and
 * survives client IP changes, so every datagram carries a fixed per-connection
 * header:
 *
 *   [0:2]   big-endian length of the first IMP message (self-inclusive)
 *   [2]     0x4c   constant magic
 *   [3]     message type/flags (small)
 *   [4:6]   16-bit connection id, constant per direction, differs by direction
 *   [6:8]   16-bit per-direction sequence counter
 *   [8:12]  peer connection id + sequence (mirror of the other direction)
 *   [12:16] 32-bit session token, constant per direction, differs by direction
 *
 * The payload is encrypted; detection keys on the framing invariants only,
 * verifying that the connection id and session token are constant within a
 * direction and differ across directions (same approach as hamachi.c).
 */

#define NETMOTION_MIN_LEN  16
#define NETMOTION_MAGIC    0x4c

static void ndpi_int_netmotion_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                              struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found NetMotion\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NETMOTION,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_netmotion(struct ndpi_detection_module_struct *ndpi_struct,
                                  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  u_int16_t len_field, cid;
  u_int32_t token;
  u_int8_t dir;

  NDPI_LOG_DBG(ndpi_struct, "search NetMotion\n");

  if(packet->payload_packet_len < NETMOTION_MIN_LEN)
    goto exclude_netmotion;

  if(packet->payload[2] != NETMOTION_MAGIC || packet->payload[3] > 0x01)
    goto exclude_netmotion;

  /* Self-inclusive length of the first IMP message; datagrams may carry
     several messages (or be GSO-coalesced), so len_field <= payload_len. */
  len_field = ntohs(get_u_int16_t(packet->payload, 0));
  if(len_field < NETMOTION_MIN_LEN || len_field > packet->payload_packet_len)
    goto exclude_netmotion;

  cid = ntohs(get_u_int16_t(packet->payload, 4));
  token = ntohl(get_u_int32_t(packet->payload, 12));
  dir = packet->packet_direction;

  if(flow->l4.udp.netmotion_stage == 0) {
    flow->l4.udp.netmotion_cid[dir] = cid;
    flow->l4.udp.netmotion_token[dir] = token;
    flow->l4.udp.netmotion_stage = dir ? 2 : 1;
    return;
  }

  if(flow->l4.udp.netmotion_stage == 1 || flow->l4.udp.netmotion_stage == 2) {
    u_int8_t stored_dir = flow->l4.udp.netmotion_stage - 1;

    if(dir == stored_dir) {
      if(cid != flow->l4.udp.netmotion_cid[dir] ||
         token != flow->l4.udp.netmotion_token[dir])
        goto exclude_netmotion;
      return; /* still waiting for the opposite direction */
    }

    /* Opposite direction: the connection id and token must differ. */
    if(cid == flow->l4.udp.netmotion_cid[stored_dir] ||
       token == flow->l4.udp.netmotion_token[stored_dir])
      goto exclude_netmotion;

    flow->l4.udp.netmotion_cid[dir] = cid;
    flow->l4.udp.netmotion_token[dir] = token;
    flow->l4.udp.netmotion_stage = 3;
    return;
  }

  if(flow->l4.udp.netmotion_stage == 3) {
    if(cid != flow->l4.udp.netmotion_cid[dir] ||
       token != flow->l4.udp.netmotion_token[dir])
      goto exclude_netmotion;

    ndpi_int_netmotion_add_connection(ndpi_struct, flow);
    return;
  }

exclude_netmotion:
  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_netmotion_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("NetMotion", ndpi_struct,
                          ndpi_search_netmotion,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                          DISSECTOR_LICENSE_LGPL,
                          1, NDPI_PROTOCOL_NETMOTION);
}
