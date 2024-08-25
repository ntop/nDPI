/*
 * trdp.c
 *
 * Train Real Time Data Protocol (IEC61375-2-3)
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TRDP

#include "ndpi_api.h"
#include "ndpi_private.h"

#define TRDP_MD_HDR_LEN 116
#define TRDP_PD_HDR_LEN 40

static void ndpi_int_trdp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                         struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found TRDP\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TRDP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_trdp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search TRDP\n");

  if (packet->payload_packet_len >= TRDP_PD_HDR_LEN)
  {
    u_int32_t header_fcs = 0;
    u_int32_t dataset_len = 0;
    
    if (!packet->tcp && packet->payload[6] == 'P') { /* Process Data */
      dataset_len = ntohl(get_u_int32_t(packet->payload, 20));
      if ((u_int32_t)(packet->payload_packet_len-TRDP_PD_HDR_LEN) == dataset_len &&
          get_u_int32_t(packet->payload, 24) == 0) /* Reserved, must be zero */
      {
        header_fcs = ndpi_crc32(packet->payload, TRDP_PD_HDR_LEN-4, 0);
        if (header_fcs == le32toh(get_u_int32_t(packet->payload, TRDP_PD_HDR_LEN-4))) {
          ndpi_int_trdp_add_connection(ndpi_struct, flow);
          return;
        }
      }
    }

    if (packet->payload_packet_len >= TRDP_MD_HDR_LEN && packet->payload[6] == 'M') { /* Message Data */
      dataset_len = ntohl(get_u_int32_t(packet->payload, 20));
      u_int32_t padding = (4 - (dataset_len % 4)) % 4;

      if ((u_int32_t)(packet->payload_packet_len - TRDP_MD_HDR_LEN - padding) == dataset_len)
      {
        header_fcs = ndpi_crc32(packet->payload, TRDP_MD_HDR_LEN-4, 0);
        if (header_fcs == le32toh(get_u_int32_t(packet->payload, TRDP_MD_HDR_LEN-4))) {
          ndpi_int_trdp_add_connection(ndpi_struct, flow);
          return;
        }
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_trdp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("TRDP", ndpi_struct, *id,
                                      NDPI_PROTOCOL_TRDP,
                                      ndpi_search_trdp,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
