/*
 * iec62056.c
 *
 * IEC 62056-4-7 DLMS/COSEM transport layer for IP networks
 * 
 * Copyright (C) 2023 - ntop.org
 * Copyright (C) 2023 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_IEC62056

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_iec62056_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                             struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found IEC62056\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_IEC62056, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_iec62056(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search IEC62056\n");

  if (packet->payload_packet_len > 8 && /* Smallest suitable packet (SNRM request) is 9 bytes long */
      packet->payload[0] == 0x7E && packet->payload[1] == 0xA0 && /* HDLC frame start */
      packet->payload[packet->payload_packet_len-1] == 0x7E) /* HDLC frame end */
  {
    u_int16_t fcs = le16toh(ndpi_crc16_x25(&packet->payload[1], packet->payload_packet_len-4));
    if (fcs == get_u_int16_t(packet->payload, packet->payload_packet_len-3)) {
      ndpi_int_iec62056_add_connection(ndpi_struct,  flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_iec62056_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("IEC62056", ndpi_struct, *id,
                                      NDPI_PROTOCOL_IEC62056,
                                      ndpi_search_iec62056,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
