/*
 * natpmp.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NATPMP

#include "ndpi_api.h"
#include "ndpi_private.h"

#define NATPMP_PORT 5351

enum natpmp_type {
  NATPMP_REQUEST_ADDRESS      = 0x00,
  NATPMP_REQUEST_UDP_MAPPING  = 0x01,
  NATPMP_REQUEST_TCP_MAPPING  = 0x02,
  NATPMP_RESPONSE_ADDRESS     = 0x80,
  NATPMP_RESPONSE_UDP_MAPPING = 0x81,
  NATPMP_RESPONSE_TCP_MAPPING = 0x82
};

static int ndpi_search_natpmp_extra(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow);

static void ndpi_int_natpmp_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                           struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found nat-pmp\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_NATPMP,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
  if (flow->extra_packets_func == NULL)
  {
    flow->max_extra_packets_to_check = 5;
    flow->extra_packets_func = ndpi_search_natpmp_extra;
  }
}

static void natpmp_disable_extra_dissection(struct ndpi_flow_struct * const flow)
{
  flow->max_extra_packets_to_check = 0;
  flow->extra_packets_func = NULL;
}

static int natpmp_is_common_header(struct ndpi_packet_struct const * const packet)
{
  return packet->payload_packet_len >= 2 && packet->payload[0] == 0x00 /* Protocol version: 0x00 */;
}

static int natpmp_is_valid(struct ndpi_packet_struct const * const packet, enum natpmp_type * const natpmp_type)
{
  if (natpmp_is_common_header(packet) == 0)
  {
    return 0;
  }

  *natpmp_type = packet->payload[1];
  switch (*natpmp_type)
  {
    case NATPMP_REQUEST_ADDRESS:
      if (packet->payload_packet_len != 2)
      {
        return 0;
      }
      break;
    case NATPMP_REQUEST_UDP_MAPPING:
    case NATPMP_REQUEST_TCP_MAPPING:
      if (packet->payload_packet_len != 12 || get_u_int16_t(packet->payload, 2) != 0x0000)
      {
        return 0;
      }
      break;
    case NATPMP_RESPONSE_ADDRESS:
    case NATPMP_RESPONSE_UDP_MAPPING:
    case NATPMP_RESPONSE_TCP_MAPPING:
      if ((*natpmp_type == NATPMP_RESPONSE_ADDRESS && packet->payload_packet_len != 12) ||
          (*natpmp_type != NATPMP_RESPONSE_ADDRESS && packet->payload_packet_len != 16))
      {
        return 0;
      }

      {
        u_int16_t result_code = ntohs(get_u_int16_t(packet->payload, 2));
        if (result_code > 5)
        {
          return 0;
        }
      }
      break;

    default:
      return 0;
  }

  return 1;
}

static int ndpi_search_natpmp_extra(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  enum natpmp_type natpmp_type;

  if (natpmp_is_valid(packet, &natpmp_type) == 0)
  {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid NATPMP Header");
    return 0;
  }

  switch (natpmp_type)
  {
    case NATPMP_REQUEST_ADDRESS:
      return 1; // Nothing to do here.
    case NATPMP_REQUEST_UDP_MAPPING:
    case NATPMP_REQUEST_TCP_MAPPING:
      flow->protos.natpmp.internal_port = ntohs(get_u_int16_t(packet->payload, 4));
      flow->protos.natpmp.external_port = ntohs(get_u_int16_t(packet->payload, 6));
      if (flow->protos.natpmp.internal_port == 0)
      {
        ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Request Port Mapping: Internal port must not 0");
      }
      break;
    case NATPMP_RESPONSE_ADDRESS:
      flow->protos.natpmp.result_code = ntohs(get_u_int16_t(packet->payload, 2));
      flow->protos.natpmp.external_address.ipv4 = get_u_int32_t(packet->payload, 8);
      if (flow->protos.natpmp.result_code != 0 && flow->protos.natpmp.external_address.ipv4 != 0)
      {
        ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Address Response: Result code indicates an error, but External IPv4 Address is set");
      }
      break;
    case NATPMP_RESPONSE_UDP_MAPPING:
    case NATPMP_RESPONSE_TCP_MAPPING:
    {
      flow->protos.natpmp.internal_port = ntohs(get_u_int16_t(packet->payload, 8));
      flow->protos.natpmp.external_port = ntohs(get_u_int16_t(packet->payload, 10));
      if (flow->protos.natpmp.internal_port == 0 || flow->protos.natpmp.external_port == 0)
      {
        ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Port Mapping Response: Internal/External port must not 0");
      }
      break;
    }
  }

  return 1;
}

static void ndpi_search_natpmp(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  enum natpmp_type natpmp_type;

  NDPI_LOG_DBG(ndpi_struct, "search nat-pmp\n");

  if (natpmp_is_valid(packet, &natpmp_type) == 0)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if ((flow->packet_counter > 2 && natpmp_type != NATPMP_REQUEST_ADDRESS) ||
      ntohs(packet->udp->source) == NATPMP_PORT || ntohs(packet->udp->dest) == NATPMP_PORT)
  {
    ndpi_int_natpmp_add_connection(ndpi_struct, flow);
    if (ndpi_search_natpmp_extra(ndpi_struct, flow) == 0)
    {
      natpmp_disable_extra_dissection(flow);
    }
  }
}

void init_natpmp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("NAT-PMP", ndpi_struct, *id,
    NDPI_PROTOCOL_NATPMP,
    ndpi_search_natpmp,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );

  *id += 1;
}
