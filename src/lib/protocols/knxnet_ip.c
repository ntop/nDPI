/*
 * knxnet_ip.c
 *
 * KNXnet/IP
 * 
 * Copyright (C) 2024 - ntop.org
 * Copyright (C) 2024 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_KNXNET_IP

#include "ndpi_api.h"
#include "ndpi_private.h"

enum knx_service_families {
  KNX_SERVICE_CORE                    = 0x02,
  KNX_SERVICE_MANAGEMENT              = 0x03,
  KNX_SERVICE_TUNNELING               = 0x04,
  KNX_SERVICE_ROUTING                 = 0x05,
  KNX_SERVICE_REMOTE_LOGGING          = 0x06,
  KNX_SERVICE_REMOTE_DIAG_AND_CONFIG  = 0x07,
  KNX_SERVICE_OBJECT_SERVER           = 0x08,
  KNX_SERVICE_SECURITY                = 0x09
};

static inline int is_valid_knxnet_ip_service_id(u_int16_t service_id) {
  u_int8_t service_family = service_id >> 8;
  u_int8_t service_code = service_id & 0xFF;

  switch (service_family)
  {
    case KNX_SERVICE_CORE:
      return (service_code > 0 && service_code < 0xD);
    case KNX_SERVICE_MANAGEMENT:
      return (service_code >= 0x10 && service_code <= 0x11);
    case KNX_SERVICE_TUNNELING:
      return (service_code >= 0x20 && service_code <= 0x25);
    case KNX_SERVICE_ROUTING:
      return (service_code >= 0x30 && service_code <= 0x33);
    case KNX_SERVICE_REMOTE_DIAG_AND_CONFIG:
      return (service_code >= 0x40 && service_code <= 0x43);
    case KNX_SERVICE_SECURITY:
      return (service_code >= 0x50 && service_code <= 0x55);
    default:
      return 0;
  }
}

static void ndpi_int_knxnet_ip_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found KNXnet/IP\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_KNXNET_IP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_knxnet_ip(struct ndpi_detection_module_struct *ndpi_struct,
                                  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search KNXnet/IP\n");

  if ((packet->payload_packet_len < 10) || (packet->payload[0] != 0x06) ||
      (packet->payload[1] != 0x10))
  {
    goto not_knxnet_ip;
  }

  u_int16_t service_id = ntohs(get_u_int16_t(packet->payload, 2));
  u_int16_t total_length = ntohs(get_u_int16_t(packet->payload, 4));

  if (!is_valid_knxnet_ip_service_id(service_id))
  {
    goto not_knxnet_ip;
  }

  if (total_length == packet->payload_packet_len)
  {
    ndpi_int_knxnet_ip_add_connection(ndpi_struct, flow);
    return;
  }

  /* Could it be a TCP packet containing multiple messages? */
  if (packet->tcp != NULL)
  {
    if ((total_length + 10) > packet->payload_packet_len)
    {
      goto not_knxnet_ip;
    }

    if (ntohs(get_u_int16_t(packet->payload, total_length)) == 0x610 &&
        is_valid_knxnet_ip_service_id(ntohs(get_u_int16_t(packet->payload, total_length+2))))
    {
      ndpi_int_knxnet_ip_add_connection(ndpi_struct, flow);
      return;
    }
  }

not_knxnet_ip:
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_knxnet_ip_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("KNXnet_IP", ndpi_struct, *id,
                                      NDPI_PROTOCOL_KNXNET_IP,
                                      ndpi_search_knxnet_ip,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
