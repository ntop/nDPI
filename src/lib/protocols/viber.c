/*
 * viber.c 
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 * Copyright (C) 2013-18 - ntop.org
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
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_VIBER

#include "ndpi_api.h"


static void viber_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Viber\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_VIBER,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_viber(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  
  NDPI_LOG_DBG(ndpi_struct, "search for Viber\n");

  if (packet->tcp != NULL)
  {
    NDPI_LOG_DBG2(ndpi_struct, "searching Viber over tcp\n");

    if (packet->payload_packet_len >= 11 &&
        le16toh(get_u_int16_t(packet->payload, 0)) == packet->payload_packet_len)
    {
      if (ntohs(get_u_int16_t(packet->payload, 6)) == 0xfcff &&
          packet->payload[9] == 0x80)
      {
        viber_add_connection(ndpi_struct, flow);
        return;
      }
      if (ntohs(get_u_int16_t(packet->payload, 4)) == 0x0380 &&
          packet->payload[10] == 0x0a)
      {
        viber_add_connection(ndpi_struct, flow);
        return;
      }
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if((packet->udp != NULL) && (packet->payload_packet_len > 5)) {
    NDPI_LOG_DBG2(ndpi_struct, "calculating dport over udp\n");

    if((packet->payload[2] == 0x03 && packet->payload[3] == 0x00)
       || (packet->payload_packet_len == 20 && packet->payload[2] == 0x09 && packet->payload[3] == 0x00)
       || (packet->payload[2] == 0x01 && packet->payload[3] == 0x00 && packet->payload[4] == 0x05 && packet->payload[5] == 0x00)
       || (packet->payload_packet_len == 34 && packet->payload[2] == 0x19 && packet->payload[3] == 0x00)
       || (packet->payload_packet_len == 34 && packet->payload[2] == 0x1b && packet->payload[3] == 0x00)
       )
    {
      viber_add_connection(ndpi_struct, flow);
      return;
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
}


void init_viber_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id) 
{
  ndpi_set_bitmask_protocol_detection("Viber", ndpi_struct, *id,
				      NDPI_PROTOCOL_VIBER,
				      ndpi_search_viber,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

