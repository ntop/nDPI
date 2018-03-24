/*
 * zmq.c
 *
 * Copyright (C) 2016 - ntop.org
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
#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_ZMQ
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ZMQ

#include "ndpi_api.h"

static void ndpi_int_zmq_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZMQ, NDPI_PROTOCOL_UNKNOWN);
  NDPI_LOG_INFO(ndpi_struct, "found ZMQ\n");
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
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
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

  NDPI_LOG_DBG(ndpi_struct, "search ZMQ\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_ZMQ) {
    if(packet->tcp && packet->tcp_retransmission == 0) {
      ndpi_check_zmq(ndpi_struct, flow);
    }
  }
}


void init_zmq_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("ZeroMQ", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_ZMQ,
				      ndpi_search_zmq, /* TODO: add UDP support */
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
