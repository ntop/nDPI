/*
 * imesh.c
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


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_IMESH


static void ndpi_int_imesh_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					  struct ndpi_flow_struct *flow, ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_IMESH, protocol_type);
}


void ndpi_search_imesh_tcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;	

  if (packet->udp != NULL) {

    NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "UDP FOUND\n");

    // this is the login packet
    if (packet->payload_packet_len == 28 && (get_u_int32_t(packet->payload, 0)) == htonl(0x02000000) &&
	get_u_int32_t(packet->payload, 24) == 0 &&
	(packet->udp->dest == htons(1864) || packet->udp->source == htons(1864))) {
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "iMesh Login detected\n");
      ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }
    if (packet->payload_packet_len == 36) {
      if (get_u_int32_t(packet->payload, 0) == htonl(0x02000000) && packet->payload[4] != 0 &&
	  packet->payload[5] == 0 && get_u_int16_t(packet->payload, 6) == htons(0x0083) &&
	  get_u_int32_t(packet->payload, 24) == htonl(0x40000000) &&
	  (packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] ||
	   packet->payload[packet->payload_packet_len - 1] - 1 == packet->payload[packet->payload_packet_len - 5]
	   || packet->payload[packet->payload_packet_len - 1] ==
	   packet->payload[packet->payload_packet_len - 5] - 1)) {
	NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "iMesh detected\n");
	ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
	return;
      }
      if (get_u_int16_t(packet->payload, 0) == htons(0x0200) && get_u_int16_t(packet->payload, 2) != 0 &&
	  get_u_int32_t(packet->payload, 4) == htonl(0x02000083) && get_u_int32_t(packet->payload, 24) == htonl(0x40000000) &&
	  (packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] ||
	   packet->payload[packet->payload_packet_len - 1] - 1 == packet->payload[packet->payload_packet_len - 5]
	   || packet->payload[packet->payload_packet_len - 1] ==
	   packet->payload[packet->payload_packet_len - 5] - 1)) {
	NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "iMesh detected\n");
	ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
	return;
      }
    }
    if (packet->payload_packet_len == 24 && get_u_int16_t(packet->payload, 0) == htons(0x0200)
	&& get_u_int16_t(packet->payload, 2) != 0 && get_u_int32_t(packet->payload, 4) == htonl(0x03000084) &&
	(packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] ||
	 packet->payload[packet->payload_packet_len - 1] - 1 == packet->payload[packet->payload_packet_len - 5] ||
	 packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] - 1)) {
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "iMesh detected\n");
      ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }
    if (packet->payload_packet_len == 32 && get_u_int32_t(packet->payload, 0) == htonl(0x02000000) &&
	get_u_int16_t(packet->payload, 21) == 0 && get_u_int16_t(packet->payload, 26) == htons(0x0100)) {
      if (get_u_int32_t(packet->payload, 4) == htonl(0x00000081) && packet->payload[11] == packet->payload[15] &&
	  get_l16(packet->payload, 24) == htons(packet->udp->source)) {
	/* packet->payload[28] = source address */
	NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "iMesh detected\n");
	ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
	return;
      }
      if (get_u_int32_t(packet->payload, 4) == htonl(0x01000082)) {
	NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "iMesh detected\n");
	ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
	return;
      }
    }
    NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "iMesh UDP packetlen: %d\n",
	     packet->payload_packet_len);

  }

  if (packet->tcp != NULL) {
    if (packet->payload_packet_len == 64 && get_u_int32_t(packet->payload, 0) == htonl(0x40000000) &&
	get_u_int32_t(packet->payload, 4) == 0 && get_u_int32_t(packet->payload, 8) == htonl(0x0000fcff) &&
	get_u_int32_t(packet->payload, 12) == htonl(0x04800100) && get_u_int32_t(packet->payload, 45) == htonl(0xff020000) &&
	get_u_int16_t(packet->payload, 49) == htons(0x001a)) {
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "found imesh.\n");
      ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }
    if (packet->payload_packet_len == 95 && get_u_int32_t(packet->payload, 0) == htonl(0x5f000000) &&
	get_u_int16_t(packet->payload, 4) == 0 && get_u_int16_t(packet->payload, 7) == htons(0x0004) &&
	get_u_int32_t(packet->payload, 20) == 0 && get_u_int32_t(packet->payload, 28) == htonl(0xc8000400) &&
	packet->payload[9] == 0x80 && get_u_int32_t(packet->payload, 10) == get_u_int32_t(packet->payload, 24)) {
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "found imesh.\n");
      ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }
    if (packet->payload_packet_len == 28 && get_u_int32_t(packet->payload, 0) == htonl(0x1c000000) &&
	get_u_int16_t(packet->payload, 10) == htons(0xfcff) && get_u_int32_t(packet->payload, 12) == htonl(0x07801800) &&
	(get_u_int16_t(packet->payload, packet->payload_packet_len - 2) == htons(0x1900) ||
	 get_u_int16_t(packet->payload, packet->payload_packet_len - 2) == htons(0x1a00))) {
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "found imesh.\n");
      ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }

    NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "TCP FOUND :: Payload %u\n",
	     packet->payload_packet_len);

    if (packet->actual_payload_len == 0) {
      return;
    }
    if ((packet->actual_payload_len == 8 || packet->payload_packet_len == 10)	/* PATTERN:: 04 00 00 00 00 00 00 00 [00 00] */
	&&get_u_int32_t(packet->payload, 0) == htonl(0x04000000)
	&& get_u_int32_t(packet->payload, 4) == 0) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->actual_payload_len == 10	/* PATTERN:: ?? ?? 04|00 00 64|00 00 */
	       && (packet->payload[2] == 0x04 || packet->payload[2] == 0x00)
	       && packet->payload[3] == 0x00 && (packet->payload[4] == 0x00 || packet->payload[4] == 0x64)
	       && packet->payload[5] == 0x00
	       && (packet->payload[2] != packet->payload[4]) /* We do not want that the packet is ?? ?? 00 00 00 00 */
	       ) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->actual_payload_len == 2 && packet->payload[0] == 0x06 && packet->payload[1] == 0x00) {
      flow->l4.tcp.imesh_stage++;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->actual_payload_len == 10	/* PATTERN:: 06 00 04|00 00 01|00 00 01|00 00 ?? 00 */
	       && packet->payload[0] == 0x06
	       && packet->payload[1] == 0x00 && (packet->payload[2] == 0x04 || packet->payload[2] == 0x00)
	       && packet->payload[3] == 0x00 && (packet->payload[4] == 0x00 || packet->payload[4] == 0x01)
	       && packet->payload[5] == 0x00 && (packet->payload[6] == 0x01 || packet->payload[6] == 0x00)
	       && packet->payload[7] == 0x00 && packet->payload[9] == 0x00
	       && (packet->payload[2] || packet->payload[4] || packet->payload[6]) /* We do not want that the packet is all 06 00 00 ... */
	       ) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->actual_payload_len == 24 && packet->payload[0] == 0x06	// PATTERN :: 06 00 12 00 00 00 34 00 00
	       && packet->payload[1] == 0x00
	       && packet->payload[2] == 0x12
	       && packet->payload[3] == 0x00
	       && packet->payload[4] == 0x00
	       && packet->payload[5] == 0x00
	       && packet->payload[6] == 0x34 && packet->payload[7] == 0x00 && packet->payload[8] == 0x00) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->actual_payload_len == 8	/* PATTERN:: 06|00 00 02 00 00 00 33 00 */
	       && (packet->payload[0] == 0x06 || packet->payload[0] == 0x00)
	       && packet->payload[1] == 0x00
	       && packet->payload[2] == 0x02
	       && packet->payload[3] == 0x00
	       && packet->payload[4] == 0x00
	       && packet->payload[5] == 0x00 && packet->payload[6] == 0x33 && packet->payload[7] == 0x00) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->payload_packet_len == 6	/* PATTERN:: 02 00 00 00 33 00 */
	       && packet->payload[0] == 0x02
	       && packet->payload[1] == 0x00
	       && packet->payload[2] == 0x00
	       && packet->payload[3] == 0x00 && packet->payload[4] == 0x33 && packet->payload[5] == 0x00) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->actual_payload_len == 12 && packet->payload[0] == 0x06	// PATTERN : 06 00 06 00 00 00 64 00
	       && packet->payload[1] == 0x00
	       && packet->payload[2] == 0x06
	       && packet->payload[3] == 0x00
	       && packet->payload[4] == 0x00
	       && packet->payload[5] == 0x00 && packet->payload[6] == 0x64 && packet->payload[7] == 0x00) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->actual_payload_len == 10	/* PATTERN:: 06 00 04|01 00 00 00 01|00 00 ?? 00 */
	       && packet->payload[0] == 0x06
	       && packet->payload[1] == 0x00 && (packet->payload[2] == 0x04 || packet->payload[2] == 0x01)
	       && packet->payload[3] == 0x00
	       && packet->payload[4] == 0x00
	       && packet->payload[5] == 0x00 && (packet->payload[6] == 0x01 || packet->payload[6] == 0x00)
	       && packet->payload[7] == 0x00
	       /* && packet->payload[8]==0x00 */
	       && packet->payload[9] == 0x00) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if ((packet->actual_payload_len == 64 || packet->actual_payload_len == 52	/* PATTERN:: [len] 00 00 00 00 */
		|| packet->actual_payload_len == 95)
	       && get_u_int16_t(packet->payload, 0) == (packet->actual_payload_len)
	       && packet->payload[1] == 0x00 && packet->payload[2] == 0x00
	       && packet->payload[3] == 0x00 && packet->payload[4] == 0x00) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->actual_payload_len == 6 && packet->payload[0] == 0x06	// PATTERN : 06 00 04|6c 00|01 00 00
	       && packet->payload[1] == 0x00 && (packet->payload[2] == 0x04 || packet->payload[2] == 0x6c)
	       && (packet->payload[3] == 0x00 || packet->payload[3] == 0x01)
	       && packet->payload[4] == 0x00 && packet->payload[5] == 0x00) {

      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->actual_payload_len == 6	/* PATTERN:: [len] ?? ee 00 00 00 */
	       && get_u_int16_t(packet->payload, 0) == (packet->actual_payload_len)
	       && packet->payload[2] == 0xee
	       && packet->payload[3] == 0x00 && packet->payload[4] == 0x00 && packet->payload[5] == 0x00) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    } else if (packet->actual_payload_len == 10	/* PATTERN:: 06 00 00 00 00 00 00 00 */
	       && packet->payload[0] == 0x06
	       && packet->payload[1] == 0x00
	       && packet->payload[2] == 0x00
	       && packet->payload[3] == 0x00
	       && packet->payload[4] == 0x00
	       && packet->payload[5] == 0x00 && packet->payload[6] == 0x00 && packet->payload[7] == 0x00) {
      flow->l4.tcp.imesh_stage += 2;
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG,
	       "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
    }


    /* http login */
    if (packet->payload_packet_len > NDPI_STATICSTRING_LEN("POST /registration") &&
	memcmp(packet->payload, "POST /registration", NDPI_STATICSTRING_LEN("POST /registration")) == 0) {
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      if (packet->parsed_lines > 6 &&
	  packet->host_line.ptr != NULL &&
	  packet->host_line.len == NDPI_STATICSTRING_LEN("login.bearshare.com") &&
	  packet->line[1].ptr != NULL &&
	  packet->line[1].len == NDPI_STATICSTRING_LEN("Authorization: Basic Og==") &&
	  packet->line[4].ptr != NULL &&
	  packet->line[4].len == NDPI_STATICSTRING_LEN("Accept-Encoding: identity") &&
	  memcmp(packet->line[1].ptr, "Authorization: Basic Og==",
		 NDPI_STATICSTRING_LEN("Authorization: Basic Og==")) == 0 &&
	  memcmp(packet->host_line.ptr, "login.bearshare.com",
		 NDPI_STATICSTRING_LEN("login.bearshare.com")) == 0 &&
	  memcmp(packet->line[4].ptr, "Accept-Encoding: identity",
		 NDPI_STATICSTRING_LEN("Accept-Encoding: identity")) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "iMesh Login detected\n");
	ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_CORRELATED_PROTOCOL);
	return;
      }
    }
    /*give one packet tolerance for detection */
    if((flow->l4.tcp.imesh_stage >= 4) 
       && (flow->l4.tcp.seen_syn && flow->l4.tcp.seen_syn_ack && flow->l4.tcp.seen_ack) /* We have seen the 3-way handshake */)
      {
      NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "found imesh.\n");
      ndpi_int_imesh_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }
  }

  if ((flow->packet_counter < 5) || packet->actual_payload_len == 0) {
    return;
  }
  //imesh_not_found_end:
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_IMESH);
  NDPI_LOG(NDPI_PROTOCOL_IMESH, ndpi_struct, NDPI_LOG_DEBUG, "iMesh excluded at stage %d\n",
	   packet->tcp != NULL ? flow->l4.tcp.imesh_stage : 0);

}
#endif
