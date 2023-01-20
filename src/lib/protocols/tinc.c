/*
 * tinc.c
 *
 * Copyright (C) 2017 - William Guglielmo <william@deselmo.com>
 * Copyright (C) 2017-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TINC

#include "ndpi_api.h"
#include "libcache.h"

PACK_ON struct tinc_cache_entry {
  u_int32_t src_address;
  u_int32_t dst_address;
  u_int16_t dst_port;
} PACK_OFF;

static void ndpi_check_tinc(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;
  
  if(packet->udp != NULL) {
    if(ndpi_struct->tinc_cache != NULL) {
      struct tinc_cache_entry tinc_cache_entry1 = {
        .src_address = packet->iph->saddr,
        .dst_address = packet->iph->daddr,
        .dst_port = packet->udp->dest
      };

      struct tinc_cache_entry tinc_cache_entry2 = {
        .src_address = packet->iph->daddr,
        .dst_address = packet->iph->saddr,
        .dst_port = packet->udp->source
      };

      if(cache_remove(ndpi_struct->tinc_cache, &tinc_cache_entry1, sizeof(tinc_cache_entry1)) == CACHE_NO_ERROR ||
	 cache_remove(ndpi_struct->tinc_cache, &tinc_cache_entry2, sizeof(tinc_cache_entry2)) == CACHE_NO_ERROR) {

        cache_remove(ndpi_struct->tinc_cache, &tinc_cache_entry1, sizeof(tinc_cache_entry1));
        cache_remove(ndpi_struct->tinc_cache, &tinc_cache_entry2, sizeof(tinc_cache_entry2));

	/* cache_free(ndpi_struct->tinc_cache); */

        NDPI_LOG_INFO(ndpi_struct, "found tinc udp connection\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TINC, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_CACHE);
      }
    }
    
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  } else if(packet->tcp != NULL) {

    switch(flow->tinc_state) {
    case 0:
    case 1:
      if(payload_len > 6 && memcmp(packet_payload, "0 ", 2) == 0 && packet_payload[2] != ' ') {
	u_int32_t i = 3;
	while(i < payload_len && packet_payload[i++] != ' ');
	if(i+3 == payload_len && memcmp((packet_payload+i), "17\n", 3) == 0) {
	  flow->tinc_state++;
	  return;
	}
      }
      break;

    case 2:
    case 3:
      if(payload_len > 11 && memcmp(packet_payload, "1 ", 2) == 0 && packet_payload[2] != ' ') {
	u_int16_t i = 3;
	u_int8_t numbers_left = 4;
	while(numbers_left) {
	  while(i < payload_len && packet_payload[i] >= '0' && packet_payload[i] <= '9') {
	    i++;
	  }

	  if(i < payload_len && packet_payload[i++] == ' ') {
	    numbers_left--;
	  }
	  else break;
	}
          
	if(numbers_left) break;
          
	while(i < payload_len &&
	      ((packet_payload[i] >= '0' && packet_payload[i] <= '9') ||
	       (packet_payload[i] >= 'A' && packet_payload[i] <= 'Z'))) {
	  i++;
	}
          
	if(i < payload_len && packet_payload[i] == '\n') {
	  if(++flow->tinc_state > 3) {
	    struct tinc_cache_entry tinc_cache_entry = {
	      .src_address = flow->c_address.v4,
	      .dst_address = flow->s_address.v4,
	      .dst_port = flow->s_port,
	    };

	    if(ndpi_struct->tinc_cache == NULL)
	      ndpi_struct->tinc_cache = cache_new(TINC_CACHE_MAX_SIZE);              

	    cache_add(ndpi_struct->tinc_cache, &tinc_cache_entry, sizeof(tinc_cache_entry));
	    NDPI_LOG_INFO(ndpi_struct, "found tinc tcp connection\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TINC, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
	  }
	  return;
	}
      }
      break;
      
    default: break;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

static void ndpi_search_tinc(struct ndpi_detection_module_struct* ndpi_struct, struct ndpi_flow_struct* flow) {
  NDPI_LOG_DBG(ndpi_struct, "tinc detection\n");

  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_TINC) {
    ndpi_check_tinc(ndpi_struct, flow);
  }
}

void init_tinc_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("TINC", ndpi_struct, *id,
				      NDPI_PROTOCOL_TINC,
				      ndpi_search_tinc,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, /* TODO: IPv6? */
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

