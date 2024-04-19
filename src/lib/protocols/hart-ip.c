/*
 * hart-ip.c
 *
 * Highway Addressable Remote Transducer over IP
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HART_IP

#include "ndpi_api.h"
#include "ndpi_private.h"

struct hart_ip_hdr {
  u_int8_t version;
  u_int8_t msg_type;
  u_int8_t msg_id;
  u_int8_t status;
  u_int16_t seq_num;
  u_int16_t msg_len;
};

enum hart_ip_msg_type {
  REQUEST_MSG,
  RESPONSE_MSG,
  PUBLISH_MSG,
  NAK_MSG = 15
};

enum hart_ip_msg_id {
  SESSION_INITIATE_ID,
  SESSION_CLOSE_ID,
  KEEPALIVE_ID,
  TOKEN_PASSING_PDU_ID,
  DIRECT_PDU_ID,
  READ_AUDIT_LOG_ID
};

static void ndpi_int_hart_ip_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                            struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found HART-IP\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_HART_IP, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_hart_ip(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search HART-IP\n");
  
  if (packet->payload_packet_len < sizeof(struct hart_ip_hdr)) {
    goto not_hart_ip;
  }

  struct hart_ip_hdr const * const hart_ip_header = (struct hart_ip_hdr *)packet->payload;
  
  if (hart_ip_header->version == 1 || hart_ip_header->version == 2) {
    u_int8_t message_type = hart_ip_header->msg_type & 0xF;

    if ((message_type > PUBLISH_MSG && message_type != NAK_MSG) && 
        hart_ip_header->msg_id > READ_AUDIT_LOG_ID)
    {
      goto not_hart_ip;
    }
    
    if (ntohs(hart_ip_header->msg_len) != packet->payload_packet_len) {
      goto not_hart_ip;
    }
    
    ndpi_int_hart_ip_add_connection(ndpi_struct, flow);
    return;
  }
  
not_hart_ip:
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
