/*
 * freefire.c
 *
 * Free Fire
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FREEFIRE

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_freefire_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                             struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Free Fire\n");
  ndpi_set_detected_protocol(ndpi_struct, &flow->core, NDPI_PROTOCOL_FREEFIRE,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static int is_freefire_gameplay_port(u_int16_t port)
{
  return (port >= 10011 && port <= 10015);
}

static int is_freefire_udp_payload(const struct ndpi_packet_struct *packet)
{
  u_int8_t b2;

  if (packet->payload_packet_len < 8)
    return 0;

  /* Gameplay datagrams start with XX YY a0/a5/a7 ... */
  b2 = packet->payload[2];
  return (b2 == 0xa0 || b2 == 0xa5 || b2 == 0xa7);
}

static int is_freefire_tcp_setup(const struct ndpi_packet_struct *packet)
{
  /* First C->S control packet: 770 bytes with zeros at offsets 2-5 */
  return (packet->payload_packet_len == 770 &&
          packet->payload[2] == 0 && packet->payload[3] == 0 &&
          packet->payload[4] == 0 && packet->payload[5] == 0);
}

static int is_freefire_tcp_payload(const struct ndpi_packet_struct *packet)
{
  /* Short keepalive seen on Garena control channels */
  if (packet->payload_packet_len == 10 &&
      packet->payload[0] == 0xa0 &&
      memcmp(&packet->payload[5], "vj73p", 5) == 0)
    return 1;

  if (packet->payload_packet_len < 10)
    return 0;

  if (ndpi_memmem(packet->payload, packet->payload_packet_len,
                  "freefiremobile", NDPI_STATICSTRING_LEN("freefiremobile")))
    return 1;

  if (ndpi_memmem(packet->payload, packet->payload_packet_len,
                  "FREE FIRE", NDPI_STATICSTRING_LEN("FREE FIRE")))
    return 1;

  return 0;
}

static void ndpi_search_freefire(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Free Fire\n");

  if (packet->tcp != NULL) {
    /* Fast-exclude only when we saw the full 3-way handshake.
       Mid-flow captures fall through to string matching below. */
    if (ndpi_seen_flow_beginning(flow)) {
      if (packet->packet_direction == 0 &&
          flow->core.packet_direction_counter[0] == 1) {
        if (!is_freefire_tcp_setup(packet))
          NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
        return;
      }
    }

    if (is_freefire_tcp_payload(packet)) {
      NDPI_LOG_INFO(ndpi_struct, "found Free Fire (TCP)\n");
      ndpi_int_freefire_add_connection(ndpi_struct, flow);
      return;
    }

    if (flow->core.packet_counter >= 4)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  } else {
    u_int16_t sport = ntohs(packet->udp->source);
    u_int16_t dport = ntohs(packet->udp->dest);

    if ((is_freefire_gameplay_port(sport) || is_freefire_gameplay_port(dport)) &&
        is_freefire_udp_payload(packet)) {
      NDPI_LOG_INFO(ndpi_struct, "found Free Fire (UDP)\n");
      ndpi_int_freefire_add_connection(ndpi_struct, flow);
      return;
    }

    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  }
}

void init_freefire_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("FreeFire", ndpi_struct,
                          ndpi_search_freefire,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
			  DISSECTOR_LICENSE_LGPL,
                          1, NDPI_PROTOCOL_FREEFIRE);
}
