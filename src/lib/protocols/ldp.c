/*
 * ldp.c
 *
 * Label Distribution Protocol
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_LDP

#include "ndpi_api.h"
#include "ndpi_private.h"

enum ldp_message_types
{
  LDP_INITIALIZATION              = 0x0200,
  LDP_KEEPALIVE                   = 0x0201,
  LDP_CAPABILITY                  = 0x0202,
  LDP_ADDRESS                     = 0x0300,
  LDP_ADDRESS_WITHDRAWAL          = 0x0301,
  LDP_LABEL_MAPPING               = 0x0400,
  LDP_LABEL_REQUEST               = 0x0401,
  LDP_LABEL_WITHDRAWAL            = 0x0402,
  LDP_LABEL_RELEASE               = 0x0403,
  LDP_LABEL_ABORT_REQUEST         = 0x0404,
  LDP_CALL_SETUP                  = 0x0500,
  LDP_CALL_RELEASE                = 0x0501,
  LDP_RG_CONNECT_MESSAGE          = 0x0700,
  LDP_RG_DISCONNECT_MESSAGE       = 0x0701,
  LDP_RG_NOTIFICATION_MESSAGE     = 0x0702,
  LDP_RG_APPLICATION_DATA_MESSAGE = 0x0703
};

static void ndpi_int_ldp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                        struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found LDP\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_LDP,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_ldp(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search LDP\n");

  if (packet->payload_packet_len > 19 &&
      ntohs(get_u_int16_t(packet->payload, 0)) == 1 &&
      ntohs(get_u_int16_t(packet->payload, 2)) == (u_int16_t)(packet->payload_packet_len-4))
  {
    /* LDP Hello Message */
    if (packet->udp != NULL &&
        ntohs(get_u_int16_t(packet->payload, 10)) == 0x0100)
    {
      ndpi_int_ldp_add_connection(ndpi_struct, flow);
      return;
    }
    else if (packet->tcp != NULL) {
      u_int16_t ldp_msg_type = ntohs(get_u_int16_t(packet->payload, 10));

      /* Vendor defined message types */
      if (ldp_msg_type >= 0x3E00 && ldp_msg_type <= 0x3EFF) {
        ndpi_int_ldp_add_connection(ndpi_struct, flow);
        return;
      }

      switch (ldp_msg_type) {
        case LDP_INITIALIZATION:
        case LDP_KEEPALIVE:
        case LDP_CAPABILITY:
        case LDP_ADDRESS:
        case LDP_ADDRESS_WITHDRAWAL:
        case LDP_LABEL_MAPPING:
        case LDP_LABEL_REQUEST:
        case LDP_LABEL_WITHDRAWAL:
        case LDP_LABEL_RELEASE:
        case LDP_LABEL_ABORT_REQUEST:
        case LDP_CALL_SETUP:
        case LDP_CALL_RELEASE:
        case LDP_RG_CONNECT_MESSAGE:
        case LDP_RG_DISCONNECT_MESSAGE:
        case LDP_RG_NOTIFICATION_MESSAGE:
        case LDP_RG_APPLICATION_DATA_MESSAGE:
          ndpi_int_ldp_add_connection(ndpi_struct, flow);
          return;
        default:
          break;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_ldp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("LDP", ndpi_struct, *id,
                                      NDPI_PROTOCOL_LDP,
                                      ndpi_search_ldp,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
