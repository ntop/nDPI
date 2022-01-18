/*
 * spotify.c
 *
 * Copyright (C) 2011-18 by ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SPOTIFY

#include "ndpi_api.h"


static void ndpi_int_spotify_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					    u_int8_t due_to_correlation)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SPOTIFY, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}


static void ndpi_check_spotify(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  // const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;

  if(packet->udp != NULL) {
    u_int16_t spotify_port = htons(57621);

    if((packet->udp->source == spotify_port)
       && (packet->udp->dest == spotify_port)) {
      if(payload_len >= 7) {
	if(memcmp(packet->payload, "SpotUdp", 7) == 0) {
	  NDPI_LOG_INFO(ndpi_struct, "found spotify udp dissector\n");
	  ndpi_int_spotify_add_connection(ndpi_struct, flow, 0);
	  return;
	}
      }
    }
  } else if(packet->tcp != NULL) {

    if(payload_len >= 9 && packet->payload[0] == 0x00 && packet->payload[1] == 0x04 &&
       packet->payload[2] == 0x00 && packet->payload[3] == 0x00&&
       packet->payload[6] == 0x52 && (packet->payload[7] == 0x0e || packet->payload[7] == 0x0f) &&
       packet->payload[8] == 0x50 ) {
      NDPI_LOG_INFO(ndpi_struct, "found spotify tcp dissector\n");
      ndpi_int_spotify_add_connection(ndpi_struct, flow, 0);
    }


    if(packet->iph /* IPv4 Only: we need to support packet->iphv6 at some point */) {
      /* if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) */ {
	/*
	Spotify

	78.31.8.0 - 78.31.15.255 (78.31.8.0/22)
	AS29017

	193.235.232.0 - 193.235.235.255 (193.235.232.0/22)
	AS29017

      194.132.196.0 - 194.132.199.255 (194.132.198.147/22)
      AS43650

      194.132.176.0 - 194.132.179.255  (194.132.176.0/22)
      AS43650

      194.132.162.0 - 194.132.163.255   (194.132.162.0/24)
      AS43650
      */

	//printf("%08X - %08X\n", ntohl(packet->iph->saddr), ntohl(packet->iph->daddr));

    unsigned long src_addr = ntohl(packet->iph->saddr);
    unsigned long dst_addr = ntohl(packet->iph->daddr);
    unsigned long src_addr_masked_22 = src_addr & 0xFFFFFC00; // */22
    unsigned long dst_addr_masked_22 = dst_addr & 0xFFFFFC00; // */22
    unsigned long src_addr_masked_24 = src_addr & 0xFFFFFF00; // */24
    unsigned long dst_addr_masked_24 = dst_addr & 0xFFFFFF00; // */24

	if(   src_addr_masked_22 == 0x4E1F0800 /* 78.31.8.0 */
	   || dst_addr_masked_22 == 0x4E1F0800 /* 78.31.8.0 */
	   /* **** */
	   || src_addr_masked_22 == 0xC1EBE800 /* 193.235.232.0 */
	   || dst_addr_masked_22 == 0xC1EBE800 /* 193.235.232.0 */
       /* **** */
       || src_addr_masked_22 == 0xC284C400 /* 194.132.196.0 */
       || dst_addr_masked_22 == 0xC284C400 /* 194.132.196.0 */
       /* **** */
       || src_addr_masked_24 == 0xC284A200 /* 194.132.162.0 */
       || dst_addr_masked_24 == 0xC284A200 /* 194.132.162.0 */
	   ) {
        NDPI_LOG_INFO(ndpi_struct, "found spotify via ip range\n");
	ndpi_int_spotify_add_connection(ndpi_struct, flow, 0);
	  return;
	}
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void ndpi_search_spotify(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_DBG(ndpi_struct, "search spotify\n");

  /* skip marked packets */
  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_SPOTIFY) {
    ndpi_check_spotify(ndpi_struct, flow);
  }
}


void init_spotify_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("SPOTIFY", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SPOTIFY,
				      ndpi_search_spotify,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

