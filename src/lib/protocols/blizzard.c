/*
* blizzard.c
* 
* Copyright (C) 2015 - Matteo Bracci <matteobracci1@gmail.com>
* Copyright (C) 2015-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_BLIZZARD

#include "ndpi_api.h"
#include "ndpi_private.h"


static void search_blizzard_tcp(struct ndpi_detection_module_struct* ndpi_struct, struct ndpi_flow_struct* flow)
{
  struct ndpi_packet_struct* packet = &ndpi_struct->packet;
  char wow_string[] = "WORLD OF WARCRAFT CONNECTION";
  char overwatch2_string_c[] = "HELLO PRO CLIENT\0";
  char overwatch2_string_s[] = "HELLO PRO SERVER\0";

  NDPI_LOG_DBG(ndpi_struct, "search Blizzard\n");

  /* Generic Battle.net traffic */
  if(flow->guessed_protocol_id_by_ip == NDPI_PROTOCOL_BLIZZARD &&
     flow->s_port == htons(1119)) {
    /* Looking for the first pkt sent by the server */
    if(current_pkt_from_server_to_client(ndpi_struct, flow) &&
       packet->payload_packet_len == 2 &&
       packet->payload[0] == 0x52 && packet->payload[1] == 0x08) {
      NDPI_LOG_INFO(ndpi_struct, "Found Blizzard (battle.net)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BLIZZARD, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    } else if(flow->packet_direction_counter[packet->packet_direction] == 1) {
      return;
    }
  }

  /* Pattern found on Hearthstone */
  if(packet->payload_packet_len >= 8 &&
     le32toh(*(uint32_t *)&packet->payload[4]) == (u_int32_t)(packet->payload_packet_len - 8)) {
    NDPI_LOG_INFO(ndpi_struct, "Found Blizzard (Hearthstone)\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BLIZZARD, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }

  /* Pattern found on WoW */
  if(packet->payload_packet_len >= NDPI_STATICSTRING_LEN(wow_string) &&
     memcmp(packet->payload, wow_string, NDPI_STATICSTRING_LEN(wow_string)) == 0) {
    NDPI_LOG_INFO(ndpi_struct, "Found Blizzard (wow)\n");
    /* Which id? It should be NDPI_PROTOCOL_BLIZZARD, but we already have NDPI_PROTOCOL_WORLDOFWARCRAFT.
       Keep using the latter for the time being.... */
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WORLDOFWARCRAFT, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }

  /* Pattern found on Overwatch2 */
  if((packet->payload_packet_len == NDPI_STATICSTRING_LEN(overwatch2_string_c) &&
      memcmp(packet->payload, overwatch2_string_c, NDPI_STATICSTRING_LEN(overwatch2_string_c)) == 0) ||
     (packet->payload_packet_len == NDPI_STATICSTRING_LEN(overwatch2_string_s) &&
      memcmp(packet->payload, overwatch2_string_s, NDPI_STATICSTRING_LEN(overwatch2_string_s)) == 0)) {
    NDPI_LOG_INFO(ndpi_struct, "Found Blizzard (overwatch2)\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BLIZZARD, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }

  /* TODO: other patterns */

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

static void search_blizzard_udp(struct ndpi_detection_module_struct* ndpi_struct, struct ndpi_flow_struct* flow)
{
  struct ndpi_packet_struct* packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Blizzard\n");

  /* Patterns found on Warcraft Rumble */

  /* The last bytes are some kind of sequence number, always starting from 1 */
  if(/* First pkt send by the client */
     (packet->payload_packet_len == 18 &&
      le32toh(*(uint32_t *)&packet->payload[14]) == 1) ||
     /* First pkt send by the server */
     (packet->payload_packet_len == 15 &&
      packet->payload[14] == 1)) {
    NDPI_LOG_INFO(ndpi_struct, "Found Blizzard (Warcraft Ramble; pattern 1)\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BLIZZARD, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }
  /* First pkt send by the client */
  if(packet->payload_packet_len == 23 &&
     ndpi_match_strprefix(packet->payload, packet->payload_packet_len, "\xff\xff\xff\xff\xa3\x1f\xb6\x1e\x00\x00\x40\x01\x00\x00\x00\x00\x00\x00\x00\x04\x03\x02\x01")) {
    NDPI_LOG_INFO(ndpi_struct, "Found Blizzard (Warcraft Ramble; pattern 2)\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BLIZZARD, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }

  /* Patterns found on Overwatch2 */
  /* Some kind of ping */
  if(flow->guessed_protocol_id_by_ip == NDPI_PROTOCOL_BLIZZARD &&
     packet->payload_packet_len == 40 &&
     *(uint32_t *)&packet->payload[17] == 0 /* Seq number starting from 0 */) {
    NDPI_LOG_INFO(ndpi_struct, "Found Blizzard (overwatch2; pattern 1)\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BLIZZARD, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }
  if(flow->guessed_protocol_id_by_ip == NDPI_PROTOCOL_BLIZZARD &&
     packet->payload_packet_len == 50 &&
     ((*(uint64_t *)&packet->payload[32] == 0 && *(uint64_t *)&packet->payload[40] == 0) /* First pkt from client */ ||
      (*(uint64_t *)&packet->payload[0] == 0 && *(uint64_t *)&packet->payload[8] == 0)) /* First pkt from server */) {
    NDPI_LOG_INFO(ndpi_struct, "Found Blizzard (overwatch2; pattern 2)\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BLIZZARD, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }

  /* TODO: other patterns */

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

static void ndpi_search_blizzard(struct ndpi_detection_module_struct* ndpi_struct, struct ndpi_flow_struct* flow)
{
  if(flow->l4_proto == IPPROTO_TCP)
    search_blizzard_tcp(ndpi_struct, flow);
  else
    search_blizzard_udp(ndpi_struct, flow);
}

void init_blizzard_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Blizzard", ndpi_struct, *id,
				      NDPI_PROTOCOL_BLIZZARD, ndpi_search_blizzard,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

