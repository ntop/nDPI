/*
 * ayiya.c
 *
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

/*
  http://en.wikipedia.org/wiki/Anything_In_Anything 
  http://tools.ietf.org/html/rfc4891
*/


#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_AYIYA

struct ayiya {
  u_int8_t flags[3];
  u_int8_t next_header;
  u_int32_t epoch;
  u_int8_t identity[16];
  u_int8_t signature[20];  
};

void ndpi_search_ayiya(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->udp && (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)) {
    /* Ayiya is udp based, port 5072 */
    if ((packet->udp->source == htons(5072) || packet->udp->dest == htons(5072))
	/* check for ayiya new packet */
	&& (packet->payload_packet_len > 44)
	) {
      /* FINISH */
      struct ayiya *a = (struct ayiya*)packet->payload;
      u_int32_t epoch = ntohl(a->epoch), now;
      u_int32_t fireyears = 86400 * 365 * 5;

      now = flow->packet.tick_timestamp;

      if((epoch >= (now - fireyears)) && (epoch <= (now+86400 /* 1 day */)))      
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_AYIYA, NDPI_REAL_PROTOCOL);

      return;
    }

    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_AYIYA);
  }
}
#endif
