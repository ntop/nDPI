/*
 * zmq.c
 *
 * Copyright (C) 2011-15 - ntop.org
 *
 * nDPI is free software: you can zmqtribute it and/or modify
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

#ifdef NDPI_PROTOCOL_ZMQ

static void ndpi_int_zmq_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_ZMQ, NDPI_REAL_PROTOCOL);
  NDPI_LOG(NDPI_PROTOCOL_ZMQ, ndpi_struct, NDPI_LOG_TRACE, "ZMQ Found.\n");
}


static void ndpi_check_zmq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;
  u_char p0[] =  { 0x00, 0x00, 0x00, 0x05, 0x01, 0x66, 0x6c, 0x6f, 0x77 };
  u_char p1[] =  { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7f };
  u_char p2[] =  { 0x28, 0x66, 0x6c, 0x6f, 0x77, 0x00 };

  if(payload_len == 0) return; /* Shouldn't happen */

  /* Break after 17 packets. */
  if(flow->packet_counter > 17) {
    NDPI_LOG(NDPI_PROTOCOL_ZMQ, ndpi_struct, NDPI_LOG_TRACE, "Exclude ZMQ.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_ZMQ);
    return;
  }

  if(flow->l4.tcp.prev_zmq_pkt_len == 0) {
    flow->l4.tcp.prev_zmq_pkt_len = ndpi_min(packet->payload_packet_len, 10);
    memcpy(flow->l4.tcp.prev_zmq_pkt, packet->payload, flow->l4.tcp.prev_zmq_pkt_len);
    return; /* Too early */
  }

  if(payload_len == 2) {
    if(flow->l4.tcp.prev_zmq_pkt_len == 2) {
      if((memcmp(packet->payload, "\01\01", 2) == 0)
	 && (memcmp(flow->l4.tcp.prev_zmq_pkt, "\01\02", 2) == 0)) {
	ndpi_int_zmq_add_connection(ndpi_struct, flow);
	return;
      }
    } else if(flow->l4.tcp.prev_zmq_pkt_len == 9) {
      if((memcmp(packet->payload, "\00\00", 2) == 0)
	 && (memcmp(flow->l4.tcp.prev_zmq_pkt, p0, 9) == 0)) {
	ndpi_int_zmq_add_connection(ndpi_struct, flow);
	return;
      }
    } else if(flow->l4.tcp.prev_zmq_pkt_len == 10) {
      if((memcmp(packet->payload, "\01\02", 2) == 0)
	 && (memcmp(flow->l4.tcp.prev_zmq_pkt, p1, 10) == 0)) {
	ndpi_int_zmq_add_connection(ndpi_struct, flow);
	return;
      }
    }
  } else if(payload_len >= 10) {
    if(flow->l4.tcp.prev_zmq_pkt_len == 10) {
      if(((memcmp(packet->payload, p1, 10) == 0)
	  && (memcmp(flow->l4.tcp.prev_zmq_pkt, p1, 10) == 0))
	 || ((memcmp(&packet->payload[1], p2, sizeof(p2)) == 0)
	     && (memcmp(&flow->l4.tcp.prev_zmq_pkt[1], p2, sizeof(p2)) == 0))) {
	ndpi_int_zmq_add_connection(ndpi_struct, flow);
	return;
      }
    }
  }
}

void ndpi_search_zmq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_ZMQ, ndpi_struct, NDPI_LOG_TRACE, "ZMQ detection...\n");

  /* skip marked packets */
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_ZMQ) {
    if (packet->tcp_retransmission == 0) {
      ndpi_check_zmq(ndpi_struct, flow);
    }
  }
}

#endif
