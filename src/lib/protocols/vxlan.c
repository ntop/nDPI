/*
 * vxlan.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_VXLAN

#include "ndpi_api.h"
#include "ndpi_private.h"

/* This code handles VXLAN as per RFC 7348 */

static void ndpi_check_vxlan(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(packet->payload_packet_len >= sizeof(struct ndpi_vxlanhdr)) {

    /*
    *rfc-7348 vxlan header
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |R|R|R|R|I|R|R|R|            Reserved                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                VXLAN Network Identifier (VNI) |   Reserved    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    u_int32_t vxlan_dst_port  = ntohs(4789);
    struct ndpi_vxlanhdr *vxlanhdr = (struct ndpi_vxlanhdr *)packet->payload;
    if((packet->udp->dest == vxlan_dst_port) &&
      (vxlanhdr->flags == ntohs(0x0800)) &&
      (vxlanhdr->groupPolicy == 0x0) &&
      (vxlanhdr->reserved == 0x0)) {
      NDPI_LOG_INFO(ndpi_struct, "found vxlan\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_VXLAN, NDPI_PROTOCOL_VXLAN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  return;
}

static void ndpi_search_vxlan(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_DBG(ndpi_struct, "search vxlan\n");

  ndpi_check_vxlan(ndpi_struct, flow);
}

void init_vxlan_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("VXLAN", ndpi_struct, *id,
              NDPI_PROTOCOL_VXLAN,
              ndpi_search_vxlan,
              NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
              SAVE_DETECTION_BITMASK_AS_UNKNOWN,
              ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
