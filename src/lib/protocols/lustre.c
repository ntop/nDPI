/*
 * lustre.c
 *
 * Lustre file system
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_LUSTRE

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_lustre_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                           struct ndpi_flow_struct *flow) 
{
  NDPI_LOG_INFO(ndpi_struct, "found Lustre\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_LUSTRE, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_lustre(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Lustre\n");

  u_int32_t lnd_dst_address = 0;

  if (packet->payload_packet_len > 15) {
    u_int32_t lnet_magic = le32toh(get_u_int32_t(packet->payload, 0));
    lnd_dst_address = le32toh(get_u_int32_t(packet->payload, 8));

    if ((lnet_magic == 0x45726963 || lnet_magic == 0xacce7100) && lnd_dst_address == ntohl(packet->iph->daddr))
    {
      ndpi_int_lustre_add_connection(ndpi_struct, flow);
      return;
    }
  }

  /*
   * Mid-stream detection
   */

  if (packet->payload_packet_len > 95 && le32toh(get_u_int32_t(packet->payload, 0)) == 0xC1)
  {
    lnd_dst_address = le32toh(get_u_int32_t(packet->payload, 24));
    u_int32_t lnet_payload_len = le32toh(get_u_int32_t(packet->payload, 52));

    if (lnd_dst_address == ntohl(packet->iph->daddr) &&
        lnet_payload_len == (u_int32_t)(packet->payload_packet_len-96))
    {
      ndpi_int_lustre_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_lustre_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Lustre", ndpi_struct, *id,
				      NDPI_PROTOCOL_LUSTRE,
				      ndpi_search_lustre,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION /* Ipv4 only; Lustre doesn't support IPv6 */,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
