/*
 * freefire.c
 *
 * Free Fire
 *
 * Copyright (C) 2026 - ntop.org
 * Copyright (C) 2026 - V.G <v.gavrilov@securitycode.ru>
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
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_FREEFIRE,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static int is_freefire_gameplay_port(u_int16_t port)
{
  return (port >= 10011 && port <= 10015);
}

static int is_freefire_udp_payload(const struct ndpi_packet_struct *packet)
{
  /* Gameplay datagrams commonly start with XX YY a5/a7 ... */
  return (packet->payload_packet_len >= 8 &&
          (packet->payload[2] == 0xa5 || packet->payload[2] == 0xa7));
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
    if (is_freefire_tcp_payload(packet)) {
      NDPI_LOG_INFO(ndpi_struct, "found Free Fire (TCP)\n");
      ndpi_int_freefire_add_connection(ndpi_struct, flow);
      return;
    }

    if (flow->packet_counter >= 8)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  } else if (packet->udp != NULL) {
    u_int16_t sport = ntohs(packet->udp->source);
    u_int16_t dport = ntohs(packet->udp->dest);

    if ((is_freefire_gameplay_port(sport) || is_freefire_gameplay_port(dport)) &&
        is_freefire_udp_payload(packet)) {
      NDPI_LOG_INFO(ndpi_struct, "found Free Fire (UDP)\n");
      ndpi_int_freefire_add_connection(ndpi_struct, flow);
      return;
    }

    if (flow->packet_counter >= 4)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  } else {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  }
}

void init_freefire_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("FreeFire", ndpi_struct,
                          ndpi_search_freefire,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_FREEFIRE);
}
