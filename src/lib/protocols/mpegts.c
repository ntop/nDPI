/*
 * mpegts.c (MPEG Transport Stream)
 *          https://en.wikipedia.org/wiki/MPEG_transport_stream
 *
 * Copyright (C) 2015 - ntop.org
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

#ifdef NDPI_PROTOCOL_MPEGTS

void ndpi_search_mpegts(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG(NDPI_PROTOCOL_MPEGTS, ndpi_struct, NDPI_LOG_DEBUG, "search for MPEGTS.\n");

  if((packet->udp != NULL) && ((packet->payload_packet_len % 188) == 0)) {
    u_int i, num_chunks = packet->payload_packet_len / 188;
    u_int32_t pkt_id;
    
    for(i=0; i<num_chunks; i++) {
      u_int offset = 188 * i;

      if(packet->payload[offset] != 0x47) goto no_mpegts;
    }

    /* This looks MPEG TS */
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MPEGTS/* , NDPI_REAL_PROTOCOL */);
    return;
  }    

 no_mpegts:
  NDPI_LOG(NDPI_PROTOCOL_MPEGTS, ndpi_struct, NDPI_LOG_DEBUG, "Excluded MPEGTS.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask/* , NDPI_PROTOCOL_MPEGTS */);
}
#endif
