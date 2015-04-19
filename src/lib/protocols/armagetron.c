/*
 * armagetron.c
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



/* include files */
#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_ARMAGETRON


static void ndpi_int_armagetron_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					       struct ndpi_flow_struct *flow)
{

  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_ARMAGETRON, NDPI_REAL_PROTOCOL);
}

void ndpi_search_armagetron_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  NDPI_LOG(NDPI_PROTOCOL_ARMAGETRON, ndpi_struct, NDPI_LOG_DEBUG, "search armagetron.\n");


  if (packet->payload_packet_len > 10) {
    /* login request */
    if (get_u_int32_t(packet->payload, 0) == htonl(0x000b0000)) {
      const u_int16_t dataLength = ntohs(get_u_int16_t(packet->payload, 4));
      if (dataLength == 0 || dataLength * 2 + 8 != packet->payload_packet_len)
	goto exclude;
      if (get_u_int16_t(packet->payload, 6) == htons(0x0008)
	  && get_u_int16_t(packet->payload, packet->payload_packet_len - 2) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_ARMAGETRON, ndpi_struct, NDPI_LOG_DEBUG, "detected armagetron.\n");
	ndpi_int_armagetron_add_connection(ndpi_struct, flow);
	return;
      }
    }
    /* sync_msg */
    if (packet->payload_packet_len == 16 && get_u_int16_t(packet->payload, 0) == htons(0x001c)
	&& get_u_int16_t(packet->payload, 2) != 0) {
      const u_int16_t dataLength = ntohs(get_u_int16_t(packet->payload, 4));
      if (dataLength != 4)
	goto exclude;
      if (get_u_int32_t(packet->payload, 6) == htonl(0x00000500) && get_u_int32_t(packet->payload, 6 + 4) == htonl(0x00010000)
	  && get_u_int16_t(packet->payload, packet->payload_packet_len - 2) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_ARMAGETRON, ndpi_struct, NDPI_LOG_DEBUG, "detected armagetron.\n");
	ndpi_int_armagetron_add_connection(ndpi_struct, flow);
	return;
      }
    }

    /* net_sync combination */
    if (packet->payload_packet_len > 50 && get_u_int16_t(packet->payload, 0) == htons(0x0018)
	&& get_u_int16_t(packet->payload, 2) != 0) {
      u_int16_t val;
      const u_int16_t dataLength = ntohs(get_u_int16_t(packet->payload, 4));
      if (dataLength == 0 || dataLength * 2 + 8 > packet->payload_packet_len)
	goto exclude;
      val = get_u_int16_t(packet->payload, 6 + 2);
      if (val == get_u_int16_t(packet->payload, 6 + 6)) {
	val = ntohs(get_u_int16_t(packet->payload, 6 + 8));
	if ((6 + 10 + val + 4) < packet->payload_packet_len
	    && (get_u_int32_t(packet->payload, 6 + 10 + val) == htonl(0x00010000)
		|| get_u_int32_t(packet->payload, 6 + 10 + val) == htonl(0x00000001))
	    && get_u_int16_t(packet->payload, packet->payload_packet_len - 2) == 0) {
	  NDPI_LOG(NDPI_PROTOCOL_ARMAGETRON, ndpi_struct, NDPI_LOG_DEBUG, "detected armagetron.\n");
	  ndpi_int_armagetron_add_connection(ndpi_struct, flow);
	  return;
	}
      }
    }
  }

 exclude:
  NDPI_LOG(NDPI_PROTOCOL_ARMAGETRON, ndpi_struct, NDPI_LOG_DEBUG, "exclude armagetron.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_ARMAGETRON);
}

#endif
