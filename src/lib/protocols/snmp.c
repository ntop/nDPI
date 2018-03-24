/*
 * snmp.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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

#ifdef NDPI_PROTOCOL_SNMP

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SNMP

#include "ndpi_api.h"

static void ndpi_int_snmp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SNMP, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_snmp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search SNMP\n");
	
  if (packet->payload_packet_len > 32 && packet->payload[0] == 0x30) {
    int offset;
    u_int16_t u16;
    
    switch (packet->payload[1]) {
    case 0x81:
      offset = 3;
      break;
    case 0x82:
      offset = 4;
      break;
    default:
      if (packet->payload[1] > 0x82) {
	NDPI_LOG_DBG2(ndpi_struct, "SNMP excluded, second byte is > 0x82\n");
	goto excl;
      }
      offset = 2;
    }

    u16 = ntohs(get_u_int16_t(packet->payload, offset));
    
    if((u16 != 0x0201) && (u16 != 0x0204)) {
      NDPI_LOG_DBG2(ndpi_struct, "SNMP excluded, 0x0201/0x0204 pattern not found\n");
      goto excl;
    }

    if (packet->payload[offset + 2] >= 0x04) {
      NDPI_LOG_DBG2(ndpi_struct, "SNMP excluded, version > 3\n");
      goto excl;
    }

    if (flow->l4.udp.snmp_stage == 0) {
      if (packet->udp->dest == htons(161) || packet->udp->dest == htons(162)) {
	NDPI_LOG_INFO(ndpi_struct, "found SNMP by port\n");
	ndpi_int_snmp_add_connection(ndpi_struct, flow);
	return;
      }
      NDPI_LOG_DBG2(ndpi_struct, "SNMP stage 0\n");
      if (packet->payload[offset + 2] == 3) {
	flow->l4.udp.snmp_msg_id = ntohs(get_u_int32_t(packet->payload, offset + 8));
      } else if (packet->payload[offset + 2] == 0) {
	flow->l4.udp.snmp_msg_id = get_u_int8_t(packet->payload, offset + 15);
      } else {
	flow->l4.udp.snmp_msg_id = ntohs(get_u_int16_t(packet->payload, offset + 15));
      }
      flow->l4.udp.snmp_stage = 1 + packet->packet_direction;
      return;
    } else if (flow->l4.udp.snmp_stage == 1 + packet->packet_direction) {
      if (packet->payload[offset + 2] == 0) {
	if (flow->l4.udp.snmp_msg_id != get_u_int8_t(packet->payload, offset + 15) - 1) {
	  NDPI_LOG_DBG2(ndpi_struct,
		   "SNMP v1 excluded, message ID doesn't match\n");
	  goto excl;
	}
      }
    } else if (flow->l4.udp.snmp_stage == 2 - packet->packet_direction) {
      NDPI_LOG_DBG2(ndpi_struct, "SNMP stage 1-2\n");
      if (packet->payload[offset + 2] == 3) {
	if (flow->l4.udp.snmp_msg_id != ntohs(get_u_int32_t(packet->payload, offset + 8))) {
	  NDPI_LOG_DBG2(ndpi_struct,
		   "SNMP v3 excluded, message ID doesn't match\n");
	  goto excl;
	}
      } else if (packet->payload[offset + 2] == 0) {
	if (flow->l4.udp.snmp_msg_id != get_u_int8_t(packet->payload, offset + 15)) {
	  NDPI_LOG_DBG2(ndpi_struct,
		   "SNMP v1 excluded, message ID doesn't match\n");
	  goto excl;
	}
      } else {
	if (flow->l4.udp.snmp_msg_id != ntohs(get_u_int16_t(packet->payload, offset + 15))) {
	  NDPI_LOG_DBG2(ndpi_struct,
		   "SNMP v2 excluded, message ID doesn't match\n");
	  goto excl;
	}
      }
      NDPI_LOG_INFO(ndpi_struct, "found SNMP\n");
      ndpi_int_snmp_add_connection(ndpi_struct, flow);
      return;
    }
  }
 excl:
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

}


void init_snmp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("SNMP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SNMP,
				      ndpi_search_snmp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
