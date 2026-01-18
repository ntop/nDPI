/*
 * hcl_notes.c
 *
 * Copyright (C) 2012-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HCL_NOTES

#include "ndpi_api.h"
#include "ndpi_private.h"

/* ************************************ */

static void ndpi_check_hcl_notes(struct ndpi_detection_module_struct *ndpi_struct, 
				   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  flow->l4.tcp.hcl_notes_packet_id++;
  
  if((flow->l4.tcp.hcl_notes_packet_id == 1) &&
     ndpi_seen_flow_beginning(flow)) {
    if(payload_len > 16) {
      char hcl_notes_header[] = { 0x00, 0x00, 0x02, 0x00, 0x00, 0x40, 0x02, 0x0F };
      
      if(memcmp(&packet->payload[6], hcl_notes_header, sizeof(hcl_notes_header)) == 0) {
        NDPI_LOG_INFO(ndpi_struct, "found HCL Notes\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HCL_NOTES, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      }
      return;
    }

  } else if(flow->l4.tcp.hcl_notes_packet_id <= 3) return;

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

static void ndpi_search_hcl_notes(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_DBG(ndpi_struct, "search hcl_notes\n");

  ndpi_check_hcl_notes(ndpi_struct, flow);
}


void init_hcl_notes_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("HCL_Notes", ndpi_struct,
                     ndpi_search_hcl_notes,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_HCL_NOTES);
}

