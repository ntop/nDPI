/*
 * vhua.c
 *
 * Copyright (C) 2011-15 - ntop.org
 *
 * nDPI is free software: you can vhuatribute it and/or modify
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

/*
  http://www.vhua.com 

  Skype-like Chinese phone protocol

 */

#ifdef NDPI_PROTOCOL_VHUA

static void ndpi_int_vhua_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_VHUA, NDPI_REAL_PROTOCOL);
  NDPI_LOG(NDPI_PROTOCOL_VHUA, ndpi_struct, NDPI_LOG_TRACE, "VHUA Found.\n");
}


static void ndpi_check_vhua(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;
  u_char p0[] =  { 0x05, 0x14, 0x3a, 0x05, 0x08, 0xf8, 0xa1, 0xb1, 0x03 };

  if(payload_len == 0) return; /* Shouldn't happen */

  /* Break after 3 packets. */
  if((flow->packet_counter > 3)
     || (packet->udp == NULL)
     || (packet->payload_packet_len < sizeof(p0))) {
    NDPI_LOG(NDPI_PROTOCOL_VHUA, ndpi_struct, NDPI_LOG_TRACE, "Exclude VHUA.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_VHUA);
  } else if(memcmp(packet->payload, p0, sizeof(p0)) == 0) {
    ndpi_int_vhua_add_connection(ndpi_struct, flow);
  }
}

void ndpi_search_vhua(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_VHUA, ndpi_struct, NDPI_LOG_TRACE, "VHUA detection...\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_VHUA) {
    ndpi_check_vhua(ndpi_struct, flow);
  }
}

#endif
