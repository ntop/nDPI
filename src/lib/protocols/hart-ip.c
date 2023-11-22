/*
 * hart-ip.c
 *
 * Highway Addressable Remote Transducer over IP
 * 
 * Copyright (C) 2023 - ntop.org
 * Copyright (C) 2023 - V.G <jacendi@protonmail.com>
 * 
 * nDPI is free software: you can zmqtribute it and/or modify
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HART_IP

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_hart_ip_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found HART-IP\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HART_IP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_hart_ip(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search HART-IP\n");
  
  if ((packet->payload_packet_len > 8) && (packet->payload[0] == 0x01) &&
      (packet->payload[1] <= 0x03 || packet->payload[1] == 0x0F) &&
      (packet->payload[2] <= 0x03) &&
      (ntohs(get_u_int16_t(packet->payload, 6)) == packet->payload_packet_len))
  {
    ndpi_int_hart_ip_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_hart_ip_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("HART-IP", ndpi_struct, *id,
              NDPI_PROTOCOL_HART_IP,
              ndpi_search_hart_ip,
              NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
              SAVE_DETECTION_BITMASK_AS_UNKNOWN,
              ADD_TO_DETECTION_BITMASK);

  *id += 1;
}