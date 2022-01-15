/*
 * apple_push.c
 *
 * Copyright (C) 2018 by ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_APPLE_PUSH

#include "ndpi_api.h"

static int is_apple_push_addr(const struct ndpi_packet_struct *packet)
{
  if(packet->iph) {
    /* 17.0.0.0/8 */
    if(((ntohl(packet->iph->saddr) & 0xFF000000 /* 255.0.0.0 */) == 0x11000000) ||
       ((ntohl(packet->iph->daddr) & 0xFF000000 /* 255.0.0.0 */) == 0x11000000))
      return 1;
  } else if(packet->iphv6) {
    /* 2620:149:a44::/48 */
    if(((packet->iphv6->ip6_src.u6_addr.u6_addr32[0] == ntohl(0x26200149)) &&
        ((packet->iphv6->ip6_src.u6_addr.u6_addr32[1] & htonl (0xffff0000)) == ntohl(0x0a440000))) ||
       ((packet->iphv6->ip6_dst.u6_addr.u6_addr32[0] == ntohl(0x26200149)) &&
        ((packet->iphv6->ip6_dst.u6_addr.u6_addr32[1] & htonl (0xffff0000)) == ntohl(0x0a440000))))
      return 1;
    /* 2403:300:a42::/48 */
    if(((packet->iphv6->ip6_src.u6_addr.u6_addr32[0] == ntohl(0x24030300)) &&
        ((packet->iphv6->ip6_src.u6_addr.u6_addr32[1] & htonl (0xffff0000)) == ntohl(0x0a420000))) ||
       ((packet->iphv6->ip6_dst.u6_addr.u6_addr32[0] == ntohl(0x24030300)) &&
        ((packet->iphv6->ip6_dst.u6_addr.u6_addr32[1] & htonl (0xffff0000)) == ntohl(0x0a420000))))
      return 1;
    /* 2403:300:a51::/48 */
    if(((packet->iphv6->ip6_src.u6_addr.u6_addr32[0] == ntohl(0x24030300)) &&
        ((packet->iphv6->ip6_src.u6_addr.u6_addr32[1] & htonl (0xffff0000)) == ntohl(0x0a510000))) ||
       ((packet->iphv6->ip6_dst.u6_addr.u6_addr32[0] == ntohl(0x24030300)) &&
        ((packet->iphv6->ip6_dst.u6_addr.u6_addr32[1] & htonl (0xffff0000)) == ntohl(0x0a510000))))
      return 1;
    /* 2a01:b740:a42::/48 */
    if(((packet->iphv6->ip6_src.u6_addr.u6_addr32[0] == ntohl(0x2a0ab740)) &&
        ((packet->iphv6->ip6_src.u6_addr.u6_addr32[1] & htonl (0xffff0000)) == ntohl(0x0a420000))) ||
       ((packet->iphv6->ip6_dst.u6_addr.u6_addr32[0] == ntohl(0x2a0ab740)) &&
        ((packet->iphv6->ip6_dst.u6_addr.u6_addr32[1] & htonl (0xffff0000)) == ntohl(0x0a420000))))
      return 1;

  }
  return 0;
}


static void ndpi_check_apple_push(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  /* https://support.apple.com/en-us/HT203609 */
  if(is_apple_push_addr(packet)) {
    u_int16_t apple_push_port       = ntohs(5223);
    u_int16_t notification_apn_port = ntohs(2197);
	
    if((packet->tcp->source == apple_push_port) || (packet->tcp->dest == apple_push_port) ||
       (packet->tcp->source == notification_apn_port) || (packet->tcp->dest == notification_apn_port)) {
      NDPI_LOG_INFO(ndpi_struct, "found apple_push\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_APPLE_PUSH, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void ndpi_search_apple_push(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_DBG(ndpi_struct, "search apple_push\n");

  /* skip marked packets */
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_APPLE_PUSH)
    ndpi_check_apple_push(ndpi_struct, flow);
}


void init_apple_push_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("APPLE_PUSH", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_APPLE_PUSH,
				      ndpi_search_apple_push,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

