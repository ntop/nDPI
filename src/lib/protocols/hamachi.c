/*
 * hamachi.c
 *
 * LogMeIn Hamachi
 * 
 * Copyright (C) 2025 - ntop.org
 * Copyright (C) 2025 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HAMACHI

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_hamachi_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
                                            struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Hamachi\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HAMACHI,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void search_hamachi_tcp(struct ndpi_detection_module_struct* ndpi_struct, 
                               struct ndpi_flow_struct* flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Hamachi over TCP\n");

  if (packet->payload_packet_len > 300 &&
      ntohl(get_u_int32_t(packet->payload, 0)) == (u_int32_t)(packet->payload_packet_len-4) &&
      ntohl(get_u_int32_t(packet->payload, 12)) == 0x7B7A0DAD)
  {
    ndpi_int_hamachi_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

static void search_hamachi_udp(struct ndpi_detection_module_struct* ndpi_struct,
                               struct ndpi_flow_struct* flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Hamachi over UDP\n");

  /* Skip initial 76-byte handshake (relay mode only) */
  if (flow->packet_counter <= 2 && packet->payload_packet_len == 76)
  {
    if (get_u_int64_t(packet->payload, 0) != 0 ||
        get_u_int64_t(packet->payload, 68) != 0)
    {
      goto exclude_hamachi;
    }
    return; /* Likely Hamachi handshake */
  }

  /* Empirically observed minimum */
  if (packet->payload_packet_len < 46) {
    goto exclude_hamachi;
  }

  /* Reasonable value for heuristics */
  u_int32_t seq = ntohl(get_u_int32_t(packet->payload, 4));
  if (seq == 0 || seq > 0xFFFF) {
    goto exclude_hamachi;
  }

  u_int32_t hamachi_l = ntohl(get_u_int32_t(packet->payload, 0));
  u_int16_t hamachi_s = ntohs(get_u_int16_t(packet->payload, 8));

  if (hamachi_l == 0xFFFFFFFF || hamachi_l == 0)
  {
    goto exclude_hamachi;
  }

  u_int8_t dir = packet->packet_direction;

  /*
   * Hamachi detection logic using 4-stage state machine:
   * Stage 0: Initial state, waiting for first packet
   * Stage 1: Got packet from dir=0, waiting for dir=1 to complete verification
   * Stage 2: Got packet from dir=1, waiting for dir=0 to complete verification  
   * Stage 3: Both directions verified, protocol identified
   *
   * Each direction has constant values in bytes 0-3 and 8-9 throughout the session.
   * We need to verify consistency within each direction and collect samples from both.
   */

  if (flow->l4.udp.hamachi_stage == 0) {
    /* Store signature values from first packet and set stage based on direction */
    flow->l4.udp.hamachi_long[dir] = hamachi_l;
    flow->l4.udp.hamachi_short[dir] = hamachi_s;
    flow->l4.udp.hamachi_stage = dir ? 2 : 1; /* Stage 1 for dir=0, stage 2 for dir=1 */
    return;
  }

  if (flow->l4.udp.hamachi_stage == 1 || flow->l4.udp.hamachi_stage == 2) {
    u_int8_t stored_dir = flow->l4.udp.hamachi_stage - 1;
    /* Current packet is same direction - verify */
    if (dir == stored_dir) {
      if (hamachi_l != flow->l4.udp.hamachi_long[dir] ||
          hamachi_s != flow->l4.udp.hamachi_short[dir])
      {
        goto exclude_hamachi;
      }
      return; /* Still waiting for opposite direction */
    }

    /* Opposite direction - verify signatures differ */
    if (hamachi_l == flow->l4.udp.hamachi_long[stored_dir] ||
       hamachi_s == flow->l4.udp.hamachi_short[stored_dir])
    {
      goto exclude_hamachi;
    }

    flow->l4.udp.hamachi_long[dir] = hamachi_l;
    flow->l4.udp.hamachi_short[dir] = hamachi_s;
    flow->l4.udp.hamachi_stage = 3;
    return;
  }

  if (flow->l4.udp.hamachi_stage == 3) {
    /* Final consistency check */
    if (hamachi_l != flow->l4.udp.hamachi_long[dir] ||
        hamachi_s != flow->l4.udp.hamachi_short[dir])
    {
      goto exclude_hamachi;
    }

    ndpi_int_hamachi_add_connection(ndpi_struct, flow);
    return;
  }

exclude_hamachi:
  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

static void ndpi_search_hamachi(struct ndpi_detection_module_struct* ndpi_struct, struct ndpi_flow_struct* flow)
{
  if(flow->l4_proto == IPPROTO_TCP)
    search_hamachi_tcp(ndpi_struct, flow);
  else
    search_hamachi_udp(ndpi_struct, flow);
}

void init_hamachi_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Hamachi", ndpi_struct,
                     ndpi_search_hamachi,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                      1, NDPI_PROTOCOL_HAMACHI);
}
