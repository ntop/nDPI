/*
 * edonkey.c
 *
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
 *
 * The signature is based on the Libprotoident library.
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_EDONKEY

#include "ndpi_api.h"


static void ndpi_int_edonkey_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_EDONKEY, NDPI_PROTOCOL_UNKNOWN);
}

static int ndpi_edonkey_payload_check(const u_int8_t *data, u_int32_t len) {
  if((len >= 4) && (data[0] == 0xe3) && (data[2] == 0x00) && (data[3] == 0x00))
    return 1;
  
  if((len >= 4) && (data[0] == 0xc5) && (data[2] == 0x00) && (data[3] == 0x00))
    return 1;  
  
  if((len >= 2) && (data[0] == 0xe5) && (data[1] == 0x43))
    return 1;
  
  if((len >= 4) && (data[0] == 0xe5) && (data[1] == 0x08) && (data[2] == 0x78) && (data[3] == 0xda))
    return 1;

  if((len >= 4) && (data[0] == 0xe5) && (data[1] == 0x28) && (data[2] == 0x78) && (data[3] == 0xda))
    return 1;

  if((len >= 2) && (data[0] == 0xc5) && (data[1] == 0x90))
    return 1;

  if((len >= 2) && (data[0] == 0xc5) && (data[1] == 0x91))
    return 1;

  if((len == 2) && (data[0] == 0xc5) && (data[1] == 0x92))
    return 1;

  if((len == 2) && (data[0] == 0xc5) && (data[1] == 0x93))
    return 1;

  if((len >= 38 && len <= 70) && (data[0] == 0xc5) && (data[1] == 0x94))
    return 1;

  if((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x9a))
    return 1;

  if((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x9b))
    return 1;

  if((len == 6) && (data[0] == 0xe3) && (data[1] == 0x96))
    return 1;

  if((len <= 34 && ((len - 2) % 4 == 0)) && (data[0] == 0xe3) && (data[1] == 0x97))
    return 1;

  if((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x92))
    return 1;

  if((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x94))
    return 1;

  if((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x98))
    return 1;

  if((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x99))
    return 1;

  if((len == 6) && (data[0] == 0xe3) && (data[1] == 0xa2))
    return 1;

  if((len >= 2) && (data[0] == 0xe3) && (data[1] == 0xa3))
    return 1;

  if((len == 27) && (data[0] == 0xe4) && (data[1] == 0x00))
    return 1;

  if((len == 529) && (data[0] == 0xe4) && (data[1] == 0x08))
    return 1;

  if((len == 18) && (data[0] == 0xe4) && (data[1] == 0x01) && (data[2] == 0x00) && (data[3] == 0x00))
    return 1;

  if((len == 523) && (data[0] == 0xe4) && (data[1] == 0x09))
    return 1;

  if((len == 35) && (data[0] == 0xe4) && (data[1] == 0x21))
    return 1;

  if((len == 19) && (data[0] == 0xe4) && (data[1] == 0x4b))
    return 1;

  if((len >= 2) && (data[0] == 0xe4) && (data[1] == 0x11))
    return 1;

  if((len == 22 || len == 38 || len == 28) && (data[0] == 0xe4) && (data[1] == 0x19))
    return 1;

  if((len == 35) && (data[0] == 0xe4) && (data[1] == 0x20))
    return 1;

  if((len == 27) && (data[0] == 0xe4) && (data[1] == 0x18))
    return 1;

  if((len == 27) && (data[0] == 0xe4) && (data[1] == 0x10))
    return 1;

  if((len == 6) && (data[0] == 0xe4) && (data[1] == 0x58))
    return 1;

  if((len == 4) && (data[0] == 0xe4) && (data[1] == 0x50))
    return 1;

  if((len == 36) && (data[0] == 0xe4) && (data[1] == 0x52))
    return 1;

  if((len == 48) && (data[0] == 0xe4) && (data[1] == 0x40))
    return 1;

  if((len == 225) && (data[0] == 0xe4) && (data[1] == 0x43))
    return 1;

  if((len == 19) && (data[0] == 0xe4) && (data[1] == 0x48))
    return 1;

  if((len == 119 || len == 69 || len == 294) && (data[0] == 0xe4) && (data[1] == 0x29))
    return 1;

  if((len == 119 || len == 69 || len == 294 || len == 44 || len == 269) && (data[0] == 0xe4) && (data[1] == 0x28))
    return 1;

  return 0;
}

static void ndpi_check_edonkey(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;
 
  /* Break after 20 packets. */
  if(flow->packet_counter > 20) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if(payload_len == 0) return;
    
  /* Check if we so far detected the protocol in the request or not. */
  if(flow->edonkey_stage == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "EDONKEY stage 0: \n");

    if(ndpi_edonkey_payload_check(packet->payload, payload_len)) {
      NDPI_LOG_DBG2(ndpi_struct, "Possible EDONKEY request detected, we will look further for the response\n");

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->edonkey_stage = packet->packet_direction + 1;
    }
  } else {
    NDPI_LOG_DBG2(ndpi_struct, "EDONKEY stage %u: \n", flow->edonkey_stage);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if((flow->edonkey_stage - packet->packet_direction) == 1) {
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    if(ndpi_edonkey_payload_check(packet->payload, payload_len)) {
      NDPI_LOG_INFO(ndpi_struct, "found EDONKEY\n");
      ndpi_int_edonkey_add_connection(ndpi_struct, flow);
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to EDONKEY, resetting the stage to 0\n");
      flow->edonkey_stage = 0;
    }

  }
}

void ndpi_search_edonkey(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search EDONKEY\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_EDONKEY) {
    if(packet->tcp_retransmission == 0) {
      ndpi_check_edonkey(ndpi_struct, flow);
    }
  }
}


void init_edonkey_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("eDonkey", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_EDONKEY,
				      ndpi_search_edonkey,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

