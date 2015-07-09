/*
 * teamviewer.c
 *
 * Copyright (C) 2012 by Gianluca Costa xplico.org
 * Copyright (C) 2012-15 - ntop.org
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

#ifdef NDPI_PROTOCOL_TEAMVIEWER

static void ndpi_int_teamview_add_connection(struct ndpi_detection_module_struct
                                             *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TEAMVIEWER, NDPI_PROTOCOL_UNKNOWN);
  NDPI_LOG(NDPI_PROTOCOL_TEAMVIEWER, ndpi_struct, NDPI_LOG_TRACE, "TEAMWIEWER Found.\n");
}


void ndpi_search_teamview(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  NDPI_LOG(NDPI_PROTOCOL_TEAMVIEWER, ndpi_struct, NDPI_LOG_TRACE, "TEAMWIEWER detection...\n");
  /*
    TeamViewer
    178.77.120.0/25

    http://myip.ms/view/ip_owners/144885/Teamviewer_Gmbh.html
  */
  if(flow->packet.iph) {
    u_int32_t src = ntohl(flow->packet.iph->saddr);
    u_int32_t dst = ntohl(flow->packet.iph->daddr);

    /* 95.211.37.195 - 95.211.37.203 */
    if(((src >= 1607673283) && (src <= 1607673291))
       || ((dst >= 1607673283) && (dst <= 1607673291))
       || ((src & 0xFFFFFF80 /* 255.255.255.128 */) == 0xB24D7800 /* 178.77.120.0 */)
       || ((dst & 0xFFFFFF80 /* 255.255.255.128 */) == 0xB24D7800 /* 178.77.120.0 */)
       ) {
      ndpi_int_teamview_add_connection(ndpi_struct, flow);
      return;
    }
  }

  if(packet->payload_packet_len == 0) return;

  if (packet->udp != NULL) {
    if (packet->payload_packet_len > 13) {
      if (packet->payload[0] == 0x00 && packet->payload[11] == 0x17 && packet->payload[12] == 0x24) { /* byte 0 is a counter/seq number, and at the start is 0 */
	flow->l4.udp.teamviewer_stage++;
	if (flow->l4.udp.teamviewer_stage == 4 ||
	    packet->udp->dest == ntohs(5938) || packet->udp->source == ntohs(5938)) {
	  ndpi_int_teamview_add_connection(ndpi_struct, flow);
	}
	return;
      }
    }
  }
  else if(packet->tcp != NULL) {
    if (packet->payload_packet_len > 2) {
      if (packet->payload[0] == 0x17 && packet->payload[1] == 0x24) {
	flow->l4.udp.teamviewer_stage++;
	if (flow->l4.udp.teamviewer_stage == 4 ||
	    packet->tcp->dest == ntohs(5938) || packet->tcp->source == ntohs(5938)) {
	  ndpi_int_teamview_add_connection(ndpi_struct, flow);
	}
	return;
      }
      else if (flow->l4.udp.teamviewer_stage) {
	if (packet->payload[0] == 0x11 && packet->payload[1] == 0x30) {
	  flow->l4.udp.teamviewer_stage++;
	  if (flow->l4.udp.teamviewer_stage == 4)
	    ndpi_int_teamview_add_connection(ndpi_struct, flow);
	}
	return;
      }
    }
  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_TEAMVIEWER);
}


void init_teamviewer_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("TeamViewer", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_TEAMVIEWER,
				      ndpi_search_teamview,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
