/*
 * dnscrypt.c
 *
 * Copyright (C) 2020 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DNSCRYPT

#include "ndpi_api.h"

static void ndpi_int_dnscrypt_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                             struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DNSCRYPT, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_dnscrypt(struct ndpi_detection_module_struct *ndpi_struct,
                          struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  static char const * const dnscrypt_initial = "2\rdnscrypt";

  NDPI_LOG_DBG(ndpi_struct, "search dnscrypt\n");

  if (flow->packet_counter > 2)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }

  /* dnscrypt protocol version 1: check magic */
  if (packet->payload_packet_len >= 64 &&
      strncmp((char*)packet->payload, "r6fnvWj8", strlen("r6fnvWj8")) == 0)
  {
    ndpi_int_dnscrypt_add_connection(ndpi_struct, flow);
  }
  /* dnscrypt protocol version 1 and 2: resolver ping */
  if (packet->payload_packet_len > 13 + strlen(dnscrypt_initial) &&
      strncasecmp((char*)packet->payload + 13, dnscrypt_initial, strlen(dnscrypt_initial)) == 0)
  {
    ndpi_int_dnscrypt_add_connection(ndpi_struct, flow);
  }
}

void init_dnscrypt_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
                             NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection(
    "DNScrypt", ndpi_struct, detection_bitmask, *id,
    NDPI_PROTOCOL_DNSCRYPT, ndpi_search_dnscrypt, NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

