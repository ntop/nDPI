/*
 * rtsp.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-20 - ntop.org
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

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RTSP

#include "ndpi_api.h"


static void ndpi_int_rtsp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow/* , */
					 /* ndpi_protocol_type_t protocol_type */)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RTSP, NDPI_PROTOCOL_UNKNOWN);
}

/* this function searches for a rtsp-"handshake" over tcp or udp. */
void ndpi_search_rtsp_tcp_udp(struct ndpi_detection_module_struct
			      *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  NDPI_LOG_DBG(ndpi_struct, "search RTSP\n");

  if (flow->rtsprdt_stage == 0
      && !(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_RTCP)
      ) {
    flow->rtsprdt_stage = 1 + packet->packet_direction;
    NDPI_LOG_DBG2(ndpi_struct, "maybe handshake 1; need next packet, return\n");
    return;
  }

  if (flow->packet_counter < 3 && flow->rtsprdt_stage == 1 + packet->packet_direction) {

    NDPI_LOG_DBG2(ndpi_struct, "maybe handshake 2; need next packet\n");
    return;
  }

  if (packet->payload_packet_len > 20 && flow->rtsprdt_stage == 2 - packet->packet_direction) {
    char buf[32] = { 0 };
    u_int len = packet->payload_packet_len;

    if(len >= (sizeof(buf)-1)) len = sizeof(buf)-1;
    strncpy(buf, (const char*)packet->payload, len);

    // RTSP Server Message
    if((memcmp(packet->payload, "RTSP/1.0 ", 9) == 0)
       || (strstr(buf, "rtsp://") != NULL)) {
      NDPI_LOG_DBG2(ndpi_struct, "found RTSP/1.0 \n");
      if (dst != NULL) {
	NDPI_LOG_DBG2(ndpi_struct, "found dst\n");
	ndpi_packet_src_ip_get(packet, &dst->rtsp_ip_address);
	dst->rtsp_timer = packet->tick_timestamp;
	dst->rtsp_ts_set = 1;
      }
      if (src != NULL) {
	NDPI_LOG_DBG2(ndpi_struct, "found src\n");
	ndpi_packet_dst_ip_get(packet, &src->rtsp_ip_address);
	src->rtsp_timer = packet->tick_timestamp;
	src->rtsp_ts_set = 1;
      }
      NDPI_LOG_INFO(ndpi_struct, "found RTSP\n");
      flow->rtsp_control_flow = 1;
      ndpi_int_rtsp_add_connection(ndpi_struct, flow);
      return;
    }
  }
  if (packet->udp != NULL && packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN
      && ((NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RTP) == 0)
	  || (NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RTCP) == 0)
	  )) {
    NDPI_LOG_DBG2(ndpi_struct,
	     "maybe RTSP RTP, RTSP RTCP, RDT; need next packet.\n");
    return;
  }


  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  return;
}


void init_rtsp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("RTSP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_RTSP,
				      ndpi_search_rtsp_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
