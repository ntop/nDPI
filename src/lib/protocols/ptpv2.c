/*
 * ptpv2.c
 *
 * IEEE 1588-2008 Precision Time Protocol (PTP) Version 2
 * 
 * Copyright (C) 2023 - ntop.org
 * Copyright (C) 2023 V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_PTPV2

#include "ndpi_api.h"
#include "ndpi_private.h"

#define PTP_EVENT_MSG_PORT    319
#define PTP_GENERAL_MSG_PORT  320

static void ndpi_int_ptpv2_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PTPV2, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_ptpv2_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search PTPv2\n");

  /* PTPv2 header is 34 bytes long */
  if (packet->payload_packet_len > 34) {
    u_int16_t sport = ntohs(packet->udp->source);
    u_int16_t dport = ntohs(packet->udp->dest);

    if ((sport == PTP_EVENT_MSG_PORT && dport == PTP_EVENT_MSG_PORT) ||
        (sport == PTP_GENERAL_MSG_PORT && dport == PTP_GENERAL_MSG_PORT))
    {
      /* Check PTP version and message type */
      if (((packet->payload[0] & 0xF) < 0xF) && packet->payload[1] == 0x02) {
        NDPI_LOG_INFO(ndpi_struct, "found PTPv2\n");
        ndpi_int_ptpv2_add_connection(ndpi_struct, flow);
        return;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_ptpv2_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("PTPv2", ndpi_struct, *id,
              NDPI_PROTOCOL_PTPV2,
              ndpi_search_ptpv2_udp,
              NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
              SAVE_DETECTION_BITMASK_AS_UNKNOWN,
              ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
