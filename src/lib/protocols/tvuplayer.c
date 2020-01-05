/*
 * tvuplayer.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TVUPLAYER

#include "ndpi_api.h"

static void ndpi_int_tvuplayer_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					      struct ndpi_flow_struct *flow/* , */
					      /* ndpi_protocol_type_t protocol_type */)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TVUPLAYER, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_tvuplayer(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	

  NDPI_LOG_DBG(ndpi_struct, "search tvuplayer.  \n");

  if (packet->tcp != NULL) {
    if ((packet->payload_packet_len == 36 || packet->payload_packet_len == 24)
	&& packet->payload[0] == 0x00
	&& ntohl(get_u_int32_t(packet->payload, 2)) == 0x31323334
	&& ntohl(get_u_int32_t(packet->payload, 6)) == 0x35363837 && packet->payload[10] == 0x01) {
      NDPI_LOG_INFO(ndpi_struct, "found tvuplayer over tcp.  \n");
      ndpi_int_tvuplayer_add_connection(ndpi_struct, flow);
      return;
    }

    if (packet->payload_packet_len >= 50) {

      if (memcmp(packet->payload, "POST", 4) || memcmp(packet->payload, "GET", 3)) {
	NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);
	if (packet->user_agent_line.ptr != NULL &&
	    packet->user_agent_line.len >= 8 && (memcmp(packet->user_agent_line.ptr, "MacTVUP", 7) == 0)) {
	  NDPI_LOG_INFO(ndpi_struct, "Found user agent as MacTVUP\n");
	  ndpi_int_tvuplayer_add_connection(ndpi_struct, flow);
	  return;
	}
      }
    }
  }

  if (packet->udp != NULL) {

    if (packet->payload_packet_len == 56 &&
	packet->payload[0] == 0xff
	&& packet->payload[1] == 0xff && packet->payload[2] == 0x00
	&& packet->payload[3] == 0x01
	&& packet->payload[12] == 0x02 && packet->payload[13] == 0xff
	&& packet->payload[19] == 0x2c && ((packet->payload[26] == 0x05 && packet->payload[27] == 0x14)
					   || (packet->payload[26] == 0x14 && packet->payload[27] == 0x05))) {
      NDPI_LOG_INFO(ndpi_struct, "found tvuplayer pattern type I.  \n");
      ndpi_int_tvuplayer_add_connection(ndpi_struct, flow);
      return;
    }
    if (packet->payload_packet_len == 82
	&& packet->payload[0] == 0x00 && packet->payload[2] == 0x00
	&& packet->payload[10] == 0x00 && packet->payload[11] == 0x00
	&& packet->payload[12] == 0x01 && packet->payload[13] == 0xff
	&& packet->payload[19] == 0x14 && packet->payload[32] == 0x03
	&& packet->payload[33] == 0xff && packet->payload[34] == 0x01
	&& packet->payload[39] == 0x32 && ((packet->payload[46] == 0x05 && packet->payload[47] == 0x14)
					   || (packet->payload[46] == 0x14 && packet->payload[47] == 0x05))) {
      NDPI_LOG_INFO(ndpi_struct, "found tvuplayer pattern type II.  \n");
      ndpi_int_tvuplayer_add_connection(ndpi_struct, flow);
      return;
    }
    if (packet->payload_packet_len == 32
	&& packet->payload[0] == 0x00 && packet->payload[2] == 0x00
	&& (packet->payload[10] == 0x00 || packet->payload[10] == 0x65
	    || packet->payload[10] == 0x7e || packet->payload[10] == 0x49)
	&& (packet->payload[11] == 0x00 || packet->payload[11] == 0x57
	    || packet->payload[11] == 0x06 || packet->payload[11] == 0x22)
	&& packet->payload[12] == 0x01 && (packet->payload[13] == 0xff || packet->payload[13] == 0x01)
	&& packet->payload[19] == 0x14) {
      NDPI_LOG_INFO(ndpi_struct, "found tvuplayer pattern type III.  \n");
      ndpi_int_tvuplayer_add_connection(ndpi_struct, flow);
      return;
    }
    if (packet->payload_packet_len == 84
	&& packet->payload[0] == 0x00 && packet->payload[2] == 0x00
	&& packet->payload[10] == 0x00 && packet->payload[11] == 0x00
	&& packet->payload[12] == 0x01 && packet->payload[13] == 0xff
	&& packet->payload[19] == 0x14 && packet->payload[32] == 0x03
	&& packet->payload[33] == 0xff && packet->payload[34] == 0x01 && packet->payload[39] == 0x34) {
      NDPI_LOG_INFO(ndpi_struct, "found tvuplayer pattern type IV.  \n");
      ndpi_int_tvuplayer_add_connection(ndpi_struct, flow);
      return;
    }
    if (packet->payload_packet_len == 102
	&& packet->payload[0] == 0x00 && packet->payload[2] == 0x00
	&& packet->payload[10] == 0x00 && packet->payload[11] == 0x00
	&& packet->payload[12] == 0x01 && packet->payload[13] == 0xff
	&& packet->payload[19] == 0x14 && packet->payload[33] == 0xff && packet->payload[39] == 0x14) {
      NDPI_LOG_INFO(ndpi_struct, "found tvuplayer pattern type V.  \n");
      ndpi_int_tvuplayer_add_connection(ndpi_struct, flow);
      return;
    }
    if (packet->payload_packet_len == 62 && packet->payload[0] == 0x00 && packet->payload[2] == 0x00
	//&& packet->payload[10] == 0x00 && packet->payload[11] == 0x00
	&& packet->payload[12] == 0x03 && packet->payload[13] == 0xff
	&& packet->payload[19] == 0x32 && ((packet->payload[26] == 0x05 && packet->payload[27] == 0x14)
					   || (packet->payload[26] == 0x14 && packet->payload[27] == 0x05))) {
      NDPI_LOG_INFO(ndpi_struct, "found tvuplayer pattern type VI.  \n");
      ndpi_int_tvuplayer_add_connection(ndpi_struct, flow);
      return;
    }
    // to check, if byte 26, 27, 33,39 match
    if (packet->payload_packet_len == 60
	&& packet->payload[0] == 0x00 && packet->payload[2] == 0x00
	&& packet->payload[10] == 0x00 && packet->payload[11] == 0x00
	&& packet->payload[12] == 0x06 && packet->payload[13] == 0x00 && packet->payload[19] == 0x30) {
      NDPI_LOG_INFO(ndpi_struct, "found tvuplayer pattern type VII.  \n");
      ndpi_int_tvuplayer_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

}


void init_tvuplayer_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("TVUplayer", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_TVUPLAYER,
				      ndpi_search_tvuplayer,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
