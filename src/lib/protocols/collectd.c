/*
 * collectd.c
 *
 * Copyright (C) 2014-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_COLLECTD

#include "ndpi_api.h"


void ndpi_search_collectd(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int len = 0;

  NDPI_LOG_DBG(ndpi_struct, "search collectd\n");
  
  if (packet->udp == NULL) return;


  while(len < packet->payload_packet_len) {
    // u_int16_t elem_type = ntohs(*((u_int16_t*)&packet->payload[len]));
    u_int16_t elem_len = ntohs(*((u_int16_t*)&packet->payload[len+2]));

    if (elem_len == 0) break;

    len += elem_len;
  }

  if(len == packet->payload_packet_len) {
    NDPI_LOG_INFO(ndpi_struct, "found COLLECTD\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_COLLECTD, NDPI_PROTOCOL_UNKNOWN);
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}
