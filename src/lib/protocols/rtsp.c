/*
 * rtsp.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
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


#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_RTSP
#ifndef NDPI_PROTOCOL_RTP
#error RTSP requires RTP detection to work correctly
#endif
#ifndef NDPI_PROTOCOL_RTSP
#error RTSP requires RTSP detection to work correctly
#endif
#ifndef NDPI_PROTOCOL_RDP
#error RTSP requires RDP detection to work correctly
#endif

static void ndpi_int_rtsp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow,
					 ndpi_protocol_type_t protocol_type)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RTSP, protocol_type);
}

/* this function searches for a rtsp-"handshake" over tcp or udp. */
void ndpi_search_rtsp_tcp_udp(struct ndpi_detection_module_struct
			      *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  NDPI_LOG(NDPI_PROTOCOL_RTSP, ndpi_struct, NDPI_LOG_TRACE, "RTSP detection...\n");

  if (flow->rtsprdt_stage == 0
#ifdef NDPI_PROTOCOL_RTCP
      && !(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_RTCP)
#endif
      ) {
    flow->rtsprdt_stage = 1 + packet->packet_direction;
    NDPI_LOG(NDPI_PROTOCOL_RTSP, ndpi_struct, NDPI_LOG_DEBUG, "maybe handshake 1; need next packet, return.\n");
    return;
  }

  if (flow->packet_counter < 3 && flow->rtsprdt_stage == 1 + packet->packet_direction) {

    NDPI_LOG(NDPI_PROTOCOL_RTSP, ndpi_struct, NDPI_LOG_DEBUG, "maybe handshake 2; need next packet.\n");
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
      NDPI_LOG(NDPI_PROTOCOL_RTSP, ndpi_struct, NDPI_LOG_TRACE, "found RTSP/1.0 .\n");
      if (dst != NULL) {
	NDPI_LOG(NDPI_PROTOCOL_RTSP, ndpi_struct, NDPI_LOG_TRACE, "found dst.\n");
	ndpi_packet_src_ip_get(packet, &dst->rtsp_ip_address);
	dst->rtsp_timer = packet->tick_timestamp;
	dst->rtsp_ts_set = 1;
      }
      if (src != NULL) {
	NDPI_LOG(NDPI_PROTOCOL_RTSP, ndpi_struct, NDPI_LOG_TRACE, "found src.\n");
	ndpi_packet_dst_ip_get(packet, &src->rtsp_ip_address);
	src->rtsp_timer = packet->tick_timestamp;
	src->rtsp_ts_set = 1;
      }
      NDPI_LOG(NDPI_PROTOCOL_RTSP, ndpi_struct, NDPI_LOG_TRACE, "RTSP detected.\n");
      flow->rtsp_control_flow = 1;
      ndpi_int_rtsp_add_connection(ndpi_struct, flow, NDPI_REAL_PROTOCOL);
      return;
    }
  }
  if (packet->udp != NULL && packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN
      && ((NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RTP) == 0)
#ifdef NDPI_PROTOCOL_RTCP
	  || (NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RTCP) == 0)
#endif
	  )) {
    NDPI_LOG(NDPI_PROTOCOL_RTSP, ndpi_struct, NDPI_LOG_DEBUG,
	     "maybe RTSP RTP, RTSP RTCP, RDT; need next packet.\n");
    return;
  }


  NDPI_LOG(NDPI_PROTOCOL_RTSP, ndpi_struct, NDPI_LOG_DEBUG, "didn't find handshake, exclude.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RTSP);
  return;
}


#endif
