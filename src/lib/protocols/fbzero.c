/*
 * fbzero.c
 *
 * Copyright (C) 2018 - ntop.org
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

/* https://code.facebook.com/posts/608854979307125/building-zero-protocol-for-fast-secure-mobile-connections/ */

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FBZERO

#include "ndpi_api.h"

PACK_ON
struct fbzero_tag {
  char tag[4];
  u_int32_t tag_offset_len;
} PACK_OFF;

PACK_ON
struct fbzero_header {
  u_int8_t flags;
  char version[3];
  u_int8_t unknown;
  u_int32_t len;
  char tag[4];
  u_int16_t tag_number, _pad;
} PACK_OFF;

/* **************************************************************************** */

void ndpi_search_fbzero(struct ndpi_detection_module_struct *ndpi_struct,
			struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search FacebookZero\n");

  if(packet->payload_packet_len > sizeof(struct fbzero_header)) {
    struct fbzero_header *h = (struct fbzero_header*)packet->payload;
    struct fbzero_tag *t;
    u_int offset = sizeof(struct fbzero_header), i, data_offset, tag_number, data_prev_offset = 0;

    if((h->flags & 0x01) == 0)
      goto fbzero_not_found;

    if((h->version[0] != 'Q')
       || (h->version[1] != 'T')
       || (h->version[2] != 'V'))
      goto fbzero_not_found;

    if(h->unknown != 0x30)
      goto fbzero_not_found;

    t = (struct fbzero_tag*)&packet->payload[offset];
    tag_number = h->tag_number;
    data_offset = offset + tag_number*sizeof(struct fbzero_tag);

    if(strncmp(h->tag, "CHLO", 4))
      goto fbzero_not_found;

    for(i=0; i<h->tag_number; i++) {
#ifdef DEBUG
      printf("[FBZERO] %u) %c%c%c%c\n", i, t->tag[0], t->tag[1], t->tag[2], t->tag[3]);
#endif

      offset += sizeof(struct fbzero_tag);

      if((t->tag[0] == 'S') && (t->tag[1] == 'N')
	 && (t->tag[2] == 'I') && (t->tag[3] == '\0')) {
	char *value = (char*)&packet->payload[data_offset + data_prev_offset];
	u_int tag_len = t->tag_offset_len-data_prev_offset, max_len;
	ndpi_protocol_match_result ret_match;
	
	max_len = ndpi_min(tag_len, sizeof(flow->host_server_name)-1);

	strncpy((char*)flow->host_server_name, value, max_len);
	flow->host_server_name[max_len] = '\0';

#ifdef DEBUG
	printf("[FBZERO] SNI [@%u][len: %u][%s]\n", tag_len,
	       t->tag_offset_len-data_prev_offset, flow->host_server_name);
#endif

	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_FBZERO, NDPI_PROTOCOL_UNKNOWN);
	  
	ndpi_match_host_subprotocol(ndpi_struct, flow, (char *)flow->host_server_name,
				    strlen((const char *)flow->host_server_name),
				    &ret_match,
				    NDPI_PROTOCOL_FBZERO);
	return;
      }

      data_prev_offset = t->tag_offset_len;
      t = (struct fbzero_tag*)&packet->payload[offset];
    }

    return;
  }

 fbzero_not_found:
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* **************************************************************************** */

void init_fbzero_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			   NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("FacebookZero", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_FBZERO,
				      ndpi_search_fbzero,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

