/*
 * bitcoin.c
 *
 * Copyright (C) 2018-23 - ntop.org
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
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_BITCOIN
#include "ndpi_api.h"

/*https://en.bitcoin.it/wiki/Protocol_documentation*/
#define MAIN_NET_MAGIC           0xF9BEB4D9
#define TEST_NET_MAGIC           0xFABFB5DA
#define TEST_3_NET_MAGIC         0x0B110907
#define SIG_NET_MAGIC            0x0A03CF40
#define NAME_COIN_NET_MAGIC      0xF9BEB4FE

static void ndpi_check_bitcoin(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  if(packet->tcp != NULL) {
    if(packet->payload_packet_len >= 4) {
      if(packet->tcp->source == htons(8333) ||
         packet->tcp->dest == htons(8333)) {
        u_int32_t *to_match = (u_int32_t*)packet->payload;

        if((*to_match == MAIN_NET_MAGIC) || (*to_match == TEST_NET_MAGIC) || (*to_match == TEST_3_NET_MAGIC) ||
           (*to_match == SIG_NET_MAGIC) || (*to_match == NAME_COIN_NET_MAGIC)) {
           ndpi_snprintf(flow->flow_extra_info, sizeof(flow->flow_extra_info), "%s", "BITCOIN");
	        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BITCOIN, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
            NDPI_LOG_INFO(ndpi_struct, "found BITCOIN\n");
	        return;
        }
      }

    }
  }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ************************************************************************** */

static void ndpi_search_bitcoin(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  NDPI_LOG_DBG(ndpi_struct, "search BITCOIN\n");

  /* skip marked packets */
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_BITCOIN) {
    ndpi_check_bitcoin(ndpi_struct, flow);
  }
}

/* ************************************************************************** */

void init_bitcoin_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			   u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Bitcoin", ndpi_struct, *id,
				      NDPI_PROTOCOL_BITCOIN,
				      ndpi_search_bitcoin,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

