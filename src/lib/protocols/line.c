/*
 * line.c
 *
 * Copyright (C) 2019 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_LINE

#include "ndpi_api.h"


static void ndpi_line_report_protocol(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  /* printf("-> payload_len=%u\n", flow->packet.payload_packet_len); */

  NDPI_LOG_INFO(ndpi_struct, "found line\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_LINE, NDPI_PROTOCOL_LINE);
}

void ndpi_search_line(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search line\n");

  if (packet->iph) {
    /* 125.209.252.xxx */
    if (((ntohl(packet->iph->saddr) & 0xFFFFFF00 /* 255.255.255.0 */) == 0x7DD1FC00) ||
        ((ntohl(packet->iph->daddr) & 0xFFFFFF00 /* 255.255.255.0 */) == 0x7DD1FC00)) {
      if ((packet->payload_packet_len == 110) && (flow->packet.payload[0] == 0xB6) &&
          (flow->packet.payload[1] == 0x18) && (flow->packet.payload[2] == 0x00) &&
          (flow->packet.payload[3] == 0x6A)) {
        ndpi_line_report_protocol(ndpi_struct, flow);
        return;
      }
    }
  }

  if ((packet->payload_packet_len == 46 && ntohl(get_u_int32_t(packet->payload, 0)) == 0xb6130006) ||
      (packet->payload_packet_len == 8 && ntohl(get_u_int32_t(packet->payload, 0)) == 0xb6070004) ||
      (packet->payload_packet_len == 16 && ntohl(get_u_int32_t(packet->payload, 0)) == 0xb609000c)) {
    ndpi_line_report_protocol(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_line_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Line", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_LINE,
                                      ndpi_search_line, NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
