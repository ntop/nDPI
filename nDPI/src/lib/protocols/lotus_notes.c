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
    
    if((flow->l4.tcp.lotus_notes_packet_id == 1)
       /* We have seen the 3-way handshake */
       && flow->l4.tcp.seen_syn
       && flow->l4.tcp.seen_syn_ack
       && flow->l4.tcp.seen_ack) {
      if(payload_len > 16) {
	char lotus_notes_header[] = { 0x00, 0x00, 0x02, 0x00, 0x00, 0x40, 0x02, 0x0F };
	
	if(memcmp(&packet->payload[6], lotus_notes_header, sizeof(lotus_notes_header)) == 0) {
	  NDPI_LOG(NDPI_PROTOCOL_LOTUS_NOTES, ndpi_struct, NDPI_LOG_DEBUG, "Found lotus_notes.\n");
	  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_LOTUS_NOTES, NDPI_PROTOCOL_UNKNOWN);
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


void init_lotus_notes_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("LotusNotes", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_LOTUS_NOTES,
				      ndpi_search_lotus_notes,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
