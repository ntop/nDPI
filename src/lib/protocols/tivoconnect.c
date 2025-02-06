/*
 * tivoconnect.c
 *
 * Copyright (C) 2022-23 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TIVOCONNECT

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_tivoconnect_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                                struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found tivoconnect\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_TIVOCONNECT,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void dissect_tivoconnect_data(struct ndpi_detection_module_struct *ndpi_struct,
                                     struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  char const * const payload = (char const *)packet->payload;
  size_t const payload_len = packet->payload_packet_len;
  char const *key = payload;
  char const *newline;

  for (newline = ndpi_strnstr(payload, "\n", payload_len);
       newline != NULL;
       key = ++newline,
       newline = ndpi_strnstr(newline, "\n", payload_len - (newline - payload)))
  {
    size_t const line_len = newline - key;
    char const *value = ndpi_strnstr(key, "=", line_len);

    if (value == NULL)
    {
      ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Missing value type in TiViConnect beacon");
      continue;
    }
    value++;

    size_t const key_len = value - 1 - key;
    size_t const value_len = newline - value;

    if (key_len == NDPI_STATICSTRING_LEN("identity") &&
        strncasecmp(key, "identity", key_len) == 0)
    {
      if (value_len >= NDPI_STATICSTRING_LEN("uuid:") &&
          strncasecmp(value, "uuid:", NDPI_STATICSTRING_LEN("uuid:")) == 0)
      {
        size_t const len = ndpi_min(sizeof(flow->protos.tivoconnect.identity_uuid) - 1,
                                    value_len - NDPI_STATICSTRING_LEN("uuid:"));
        strncpy(flow->protos.tivoconnect.identity_uuid,
                value + NDPI_STATICSTRING_LEN("uuid:"), len);
        flow->protos.tivoconnect.identity_uuid[len] = '\0';
      }
      continue;
    }
    if (key_len == NDPI_STATICSTRING_LEN("machine") &&
        strncasecmp(key, "machine", key_len) == 0)
    {
      size_t const len = ndpi_min(sizeof(flow->protos.tivoconnect.machine) - 1,
                                         value_len);
      strncpy(flow->protos.tivoconnect.machine, value, len);
      flow->protos.tivoconnect.machine[len] = '\0';
      continue;
    }
    if (key_len == NDPI_STATICSTRING_LEN("platform") &&
        strncasecmp(key, "platform", key_len) == 0)
    {
      size_t const len = ndpi_min(sizeof(flow->protos.tivoconnect.platform) - 1,
                                         value_len);
      strncpy(flow->protos.tivoconnect.platform, value, len);
      flow->protos.tivoconnect.platform[len] = '\0';
      continue;
    }
    if (key_len == NDPI_STATICSTRING_LEN("services") &&
        strncasecmp(key, "services", key_len) == 0)
    {
      size_t const len = ndpi_min(sizeof(flow->protos.tivoconnect.services) - 1,
                                         value_len);
      strncpy(flow->protos.tivoconnect.services, value, len);
      flow->protos.tivoconnect.services[len] = '\0';
      continue;
    }
  }

  if ((size_t)(key - payload) != payload_len)
  {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET,
                  "TiViConnect beacon malformed packet");
  }
}

static void ndpi_search_tivoconnect(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_INFO(ndpi_struct, "search tivoconnect\n");

  if (packet->payload_packet_len >= NDPI_STATICSTRING_LEN("tivoconnect=") &&
      strncasecmp((char const *)packet->payload,
                  "tivoconnect=", NDPI_STATICSTRING_LEN("tivoconnect=")) == 0)
  {
    ndpi_int_tivoconnect_add_connection(ndpi_struct, flow);
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  dissect_tivoconnect_data(ndpi_struct, flow);
}

void init_tivoconnect_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("TiVoConnect", ndpi_struct, *id,
    NDPI_PROTOCOL_TIVOCONNECT,
    ndpi_search_tivoconnect,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );

  *id += 1;
}
