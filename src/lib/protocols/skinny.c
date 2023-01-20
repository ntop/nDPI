/*
 * skinny.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SKINNY

#include "ndpi_api.h"

/* Reference: Wiresahrk: epan/dissectors/packet-skinny.c */

static void ndpi_int_skinny_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SKINNY, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static int is_valid_version(u_int32_t version)
{
  if(version == 0x00 || /* Basic msg type */
     version == 0x0A || /* V10 */
     version == 0x0B || /* V11 */
     version == 0x0F || /* V15 */
     version == 0x10 || /* V16 */
     version == 0x11 || /* V17 */
     version == 0x12 || /* V18 */
     version == 0x13 || /* V19 */
     version == 0x14 || /* V20 */
     version == 0x15 || /* V21 */
     version == 0x16)   /* V22 */
    return 1;
  return 0;
}

static int is_valid_opcode(u_int32_t opcode)
{
  /* A loose check */
  if(opcode <= 0x009F ||
     (opcode >= 0x0100 && opcode <= 0x0160) ||
     (opcode == 0x8000) ||
     (opcode >= 0x8100 && opcode <= 0x8101))
    return 1;
  return 0;
}

static void ndpi_search_skinny(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t dport, sport;

  NDPI_LOG_DBG(ndpi_struct, "search for SKINNY\n");

  if(packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG_DBG2(ndpi_struct, "calculating SKINNY over tcp\n");
    if((dport == 2000 || sport == 2000) &&
       (packet->payload_packet_len >= 12)) {
      u_int32_t data_length, version, opcode;

      data_length = le32toh(get_u_int32_t(packet->payload, 0));
      version = le32toh(get_u_int32_t(packet->payload, 4));
      opcode = le32toh(get_u_int32_t(packet->payload, 8));

      if(data_length + 8 == packet->payload_packet_len &&
         is_valid_version(version) &&
         is_valid_opcode(opcode)) {
        NDPI_LOG_INFO(ndpi_struct, "found skinny\n");
        ndpi_int_skinny_add_connection(ndpi_struct, flow);
	return;
      }
    }
  }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_skinny_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("CiscoSkinny", ndpi_struct, *id,
				      NDPI_PROTOCOL_SKINNY,
				      ndpi_search_skinny,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
