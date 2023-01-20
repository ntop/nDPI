/*
 * tocaboca.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TOCA_BOCA

#include "ndpi_api.h"

static void ndpi_int_toca_boca_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                              struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found TocaBoca\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_TOCA_BOCA, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_toca_boca(struct ndpi_detection_module_struct *ndpi_struct,
                                  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  NDPI_LOG_DBG(ndpi_struct, "search TocaBoca\n");

  if (packet->udp != NULL)
  {
    if (payload_len >= 13
        && get_u_int32_t(packet->payload, 0) == 0x7d7d7d7d
        && get_u_int32_t(packet->payload, 4) == 0x7d7d7d7d)
    {
      ndpi_int_toca_boca_add_connection(ndpi_struct, flow);
      return;
    }

    if (flow->packet_counter == 1
        && payload_len >= 24
        && ntohl(get_u_int32_t(packet->payload, 0)) == 0xffff0001
        && ntohl(get_u_int32_t(packet->payload, 12)) == 0x02ff0104)
    {
      ndpi_int_toca_boca_add_connection(ndpi_struct, flow);
      return;
    }

    if (payload_len >= 32
        && (ntohs(get_u_int16_t(packet->payload, 2)) == 0x0001
            || ntohs(get_u_int16_t(packet->payload, 2)) == 0x0002
            || ntohs(get_u_int16_t(packet->payload, 2)) == 0x0003)
        && (ntohl(get_u_int32_t(packet->payload, 12)) == 0x01ff0000
            || ntohl(get_u_int32_t(packet->payload, 12)) == 0x01000000)
        && ntohl(get_u_int32_t(packet->payload, 16)) == 0x00000014)
    {
      ndpi_int_toca_boca_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_toca_boca_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                              u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("TocaBoca", ndpi_struct, *id,
				      NDPI_PROTOCOL_TOCA_BOCA,
				      ndpi_search_toca_boca,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

