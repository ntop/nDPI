/*
 * whatsapp.c
 *
 * Copyright (C) 2018 - ntop.org
 *
 * nDPI is free software: you can zmqtribute it and/or modify
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WHATSAPP

#include "ndpi_api.h"

void ndpi_search_whatsapp(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  static u_int8_t whatsapp_sequence[] = {
    0x45, 0x44, 0x0, 0x01, 0x0, 0x0, 0x02, 0x08,
    0x0, 0x57, 0x41, 0x02, 0x0, 0x0, 0x0
  };
  static u_int8_t whatsapp_old_sequence[] = {
    0x57, 0x41, 0x01, 0x05
  };

  NDPI_LOG_DBG(ndpi_struct, "search WhatsApp\n");

  /* This is a very old sequence (2015?) but we still have it in our unit tests.
     Try to detect it, without too much effort... */
  if(flow->l4.tcp.wa_matched_so_far == 0 &&
     packet->payload_packet_len > sizeof(whatsapp_old_sequence) &&
     memcmp(packet->payload, whatsapp_old_sequence, sizeof(whatsapp_old_sequence)) == 0) {
    NDPI_LOG_INFO(ndpi_struct, "found WhatsApp (old sequence)\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WHATSAPP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }

  if(flow->l4.tcp.wa_matched_so_far < sizeof(whatsapp_sequence)) {
    size_t match_len = sizeof(whatsapp_sequence) - flow->l4.tcp.wa_matched_so_far;
    if(packet->payload_packet_len < match_len)
	    match_len = packet->payload_packet_len;

    if(!memcmp(packet->payload, &whatsapp_sequence[flow->l4.tcp.wa_matched_so_far], match_len)) {
      flow->l4.tcp.wa_matched_so_far += match_len;
      if(flow->l4.tcp.wa_matched_so_far == sizeof(whatsapp_sequence)) {
	NDPI_LOG_INFO(ndpi_struct, "found WhatsApp\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WHATSAPP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      }
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_whatsapp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			     u_int32_t *id,
			     NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("WhatsApp", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_WHATSAPP,
				      ndpi_search_whatsapp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
