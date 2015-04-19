/*
 * lotus_notes.c
 *
 * Copyright (C) 2012-15 - ntop.org
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


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_LOTUS_NOTES

/* ************************************ */

static void ndpi_check_lotus_notes(struct ndpi_detection_module_struct *ndpi_struct, 
				   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;  
  // const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;

  if(packet->tcp != NULL) {
    flow->l4.tcp.lotus_notes_packet_id++;
    
#if 0
  printf("[lotus_notes_packet_id: %u][len=%u][%02X %02X %02X %02X %02X %02X %02X %02X]\n", 
	 flow->l4.tcp.lotus_notes_packet_id, payload_len,
	 packet->payload[6] & 0xFF,
	 packet->payload[7] & 0xFF,
	 packet->payload[8] & 0xFF,
	 packet->payload[9] & 0xFF,
	 packet->payload[10] & 0xFF,
	 packet->payload[11] & 0xFF,
	 packet->payload[12] & 0xFF,
	 packet->payload[13] & 0xFF
	 );
#endif

    if((flow->l4.tcp.lotus_notes_packet_id == 1)
       /* We have seen the 3-way handshake */
       && flow->l4.tcp.seen_syn
       && flow->l4.tcp.seen_syn_ack
       && flow->l4.tcp.seen_ack) {
      if(payload_len > 16) {
	char lotus_notes_header[] = { 0x00, 0x00, 0x02, 0x00, 0x00, 0x40, 0x02, 0x0F };
	
	if(memcmp(&packet->payload[6], lotus_notes_header, sizeof(lotus_notes_header)) == 0) {
	  NDPI_LOG(NDPI_PROTOCOL_LOTUS_NOTES, ndpi_struct, NDPI_LOG_DEBUG, "Found lotus_notes.\n");
	  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_LOTUS_NOTES, NDPI_REAL_PROTOCOL);
	}

	return;
      }

      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_LOTUS_NOTES);
    } else if(flow->l4.tcp.lotus_notes_packet_id > 3)
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_LOTUS_NOTES);
    
    return;
  }
}

void ndpi_search_lotus_notes(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_LOTUS_NOTES, ndpi_struct, NDPI_LOG_DEBUG, "lotus_notes detection...\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_LOTUS_NOTES)
    ndpi_check_lotus_notes(ndpi_struct, flow);
}

#endif
