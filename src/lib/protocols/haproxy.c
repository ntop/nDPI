/*
 * haproxy.c
 *
 * Copyright (C) 2023 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HAPROXY

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_haproxy_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HAPROXY, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static int search_proxy_protocol_v2(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  static const unsigned char pp2_sig[] = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };

  if (packet->payload_packet_len < sizeof(pp2_sig)) {
    return 0;
  }

  if (memcmp(packet->payload, pp2_sig, sizeof(pp2_sig)) == 0) {
    return 1;
  }

  return 0;
}

static void ndpi_search_haproxy(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const uint8_t *haproxy_end;

  NDPI_LOG_DBG(ndpi_struct, "search HAProxy\n");

  if (search_proxy_protocol_v2(ndpi_struct) != 0) {
    NDPI_LOG_DBG(ndpi_struct, "found HAProxy (Proxy Protocol v2)\n");
    ndpi_int_haproxy_add_connection(ndpi_struct, flow);
    return;
  }

  if (packet->payload_packet_len < NDPI_STATICSTRING_LEN("PROXY TCP"))
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if (strncmp((char *)packet->payload, "PROXY TCP", NDPI_STATICSTRING_LEN("PROXY TCP")) != 0)
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* The following code may be also used in the future to call subprotocol dissectors e.g. TLS. */
  haproxy_end = (uint8_t *)ndpi_strnstr((char *)packet->payload, "\r\n", packet->payload_packet_len);
  if (haproxy_end == NULL)
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }
  haproxy_end += 2;
  if (packet->payload_packet_len - (haproxy_end - packet->payload) == 0)
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  ndpi_int_haproxy_add_connection(ndpi_struct, flow);
}

void init_haproxy_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("HAProxy", ndpi_struct,
                     ndpi_search_haproxy,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_HAPROXY);
}
