/*
 * kxun.c
 *
 * Copyright (C) 2016 - ntop.org
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
#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_1KXUN


static void ndpi_int_kxun_add_connection(struct ndpi_detection_module_struct
					     *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_1KXUN, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_kxun(struct ndpi_detection_module_struct
			  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  /* 1KXUN over TCP is detected inside HTTP dissector */
	
  /* check 1KXUN over UDP */
  if(packet->udp != NULL) {
    /* check ipv6 */
    if(packet->iphv6 != NULL) {
      if(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0] == 0x2ff &&
	 packet->payload_packet_len == 329) {
	if(packet->payload[0] == 0xff &&
	   packet->payload[1] == 0x0f &&
	   packet->payload[4] == 0xa0 &&
	   packet->payload[5] == 0x00) {
	  NDPI_LOG(NDPI_PROTOCOL_1KXUN, ndpi_struct, NDPI_LOG_DEBUG,
		   "found 1kxun over udp.\n");
	  ndpi_int_kxun_add_connection(ndpi_struct, flow);
	  return;
	}
      }
    }
    else if(packet->iph != NULL) {
      if(packet->iph->daddr == 0xffffffff) {
	if(packet->payload_packet_len == 40 &&
	   packet->payload[8] == 0x41 &&
	   packet->payload[9] == 0x41 &&
	   packet->payload[10] == 0x42) {
	  NDPI_LOG(NDPI_PROTOCOL_1KXUN, ndpi_struct, NDPI_LOG_DEBUG,
		   "found 1kxun over udp.\n");
	  ndpi_int_kxun_add_connection(ndpi_struct, flow);
	  return;
	}
	if(packet->payload_packet_len == 317 &&
	   packet->payload[0] == 0xff &&
	   packet->payload[1] == 0xff &&
	   packet->payload[4] == 0xa0 &&
	   packet->payload[5] == 0x00) {
	  NDPI_LOG(NDPI_PROTOCOL_1KXUN, ndpi_struct, NDPI_LOG_DEBUG,
		   "found 1kxun over udp.\n");
	  ndpi_int_kxun_add_connection(ndpi_struct, flow);
	  return;
	}
      }
    }
  }
  /* EXCLUDE 1KXUN */
  NDPI_LOG(NDPI_PROTOCOL_1KXUN, ndpi_struct, NDPI_LOG_DEBUG, "exclude 1kxun.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_1KXUN);
}


void init_kxun_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("1kxun", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_1KXUN,
				      ndpi_search_kxun,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
