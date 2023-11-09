/*
 * epicgames.c
 *
 * Copyright (C) 2023 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_EPICGAMES

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_epicgames_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                              struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found EpicGames\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_PROTOCOL_EPICGAMES,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_epicgames(struct ndpi_detection_module_struct *ndpi_struct,
                                  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "searching EpicGames (stage %d dir %d)\n",
               flow->l4.udp.epicgames_stage, packet->packet_direction);

  if(flow->packet_counter == 1) {
    if(packet->payload_packet_len >= 34 &&
       ((ntohl(get_u_int32_t(packet->payload, 0)) & 0x08) == 0) &&
       get_u_int64_t(packet->payload, 10) == 0 &&
       get_u_int64_t(packet->payload, 18) == 0 &&
       get_u_int64_t(packet->payload, 26) == 0) {
      flow->l4.udp.epicgames_stage = 1 + packet->packet_direction;
      flow->l4.udp.epicgames_word = ntohl(get_u_int32_t(packet->payload, 0));
      return;
    } else {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
  } else if(flow->l4.udp.epicgames_stage == 2 - packet->packet_direction) {
    if(packet->payload_packet_len > 4 &&
       (flow->l4.udp.epicgames_word | 0x08) == ntohl(get_u_int32_t(packet->payload, 0))) {
      ndpi_int_epicgames_add_connection(ndpi_struct, flow);
      return;
    } else {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
  }

  if(flow->packet_counter >= 4) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
}

void init_epicgames_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                              u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("EpicGames", ndpi_struct, *id,
                                      NDPI_PROTOCOL_EPICGAMES,
                                      ndpi_search_epicgames,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
