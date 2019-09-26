/*
 * zoom.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ZOOM

#include "ndpi_api.h"

static u_int8_t is_zoom_tcp_port(struct ndpi_flow_struct *flow) {

  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = ntohs(packet->tcp->dest);

  if((dport == 8801) || (dport == 8802) || (dport == 5090) || (dport == 5091)){
    return 1;
  }
  return 0;
}

static u_int8_t is_zoom_udp_port(struct ndpi_flow_struct *flow) {

  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = ntohs(packet->tcp->dest);

  if((dport == 3478) || (dport == 3479) || (dport == 5090) ||
     (dport >= 8801 && dport <= 8810) || (dport >= 20000 && dport <= 64000)){
    return 1;
  }
  return 0;
}

static u_int8_t zoom_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, struct in_addr *pin) {
  return((ndpi_network_ptree_match(ndpi_struct, pin) == NDPI_PROTOCOL_ZOOM) ? 1 : 0);
}

/* ******************************************* */

static u_int8_t is_zoom_flow(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->iph) {
    struct in_addr daddr;

    daddr.s_addr = packet->iph->daddr;

    if(zoom_ptree_match(ndpi_struct, &daddr)) {
      return(1);
    }
  }

  return(0);
}

static void ndpi_check_zoom(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow) {

  struct ndpi_packet_struct *packet = &flow->packet;
    
  NDPI_LOG_DBG(ndpi_struct, "search Zoom video \n");

  if(packet->tcp != NULL)
    {
      if (is_zoom_flow(ndpi_struct, flow) && is_zoom_tcp_port(flow)){
        NDPI_LOG_INFO(ndpi_struct, "found zoom on tcp\n");

        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZOOM,
                                   NDPI_PROTOCOL_UNKNOWN);
        return;
      }
    }
  else if(packet->udp != NULL)
    {
      if (is_zoom_flow(ndpi_struct, flow) && is_zoom_udp_port(flow)){
        NDPI_LOG_INFO(ndpi_struct, "found zoom on udp\n");

        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZOOM,
                                   NDPI_PROTOCOL_UNKNOWN);
        return;
      }
    }
  else
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
}

void ndpi_search_zoom(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search zoom\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_ZOOM)
    ndpi_check_zoom(ndpi_struct, flow);
}


void init_zoom_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Zoom", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_ZOOM,
				      ndpi_search_zoom,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
