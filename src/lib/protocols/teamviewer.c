/*
 * teamviewer.c
 *
 * Copyright (C) 2012 by Gianluca Costa xplico.org
 * Copyright (C) 2012-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TEAMVIEWER

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_teamview_add_connection(struct ndpi_detection_module_struct
                                             *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TEAMVIEWER, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  NDPI_LOG_INFO(ndpi_struct, "found teamwiewer\n");
}


static void ndpi_search_teamview(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search teamwiewer\n");

  if (packet->udp != NULL) {
    if (packet->payload_packet_len > 13) {
      if (packet->payload[0] == 0x00 && packet->payload[11] == 0x17 && packet->payload[12] == 0x24) { /* byte 0 is a counter/seq number, and at the start is 0 */
	flow->teamviewer_stage++;
	if (flow->teamviewer_stage == 4 ||
	    packet->udp->dest == ntohs(5938) || packet->udp->source == ntohs(5938)) {
	  ndpi_int_teamview_add_connection(ndpi_struct, flow);
	  ndpi_set_risk(ndpi_struct, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found TeamViewer"); /* Remote assistance (UDP only) */
	}
	return;
      }
    }
  }
  else if(packet->tcp != NULL) {
    if (packet->payload_packet_len > 2) {
      if (packet->payload[0] == 0x17 && packet->payload[1] == 0x24) {
	flow->teamviewer_stage++;
	if (flow->teamviewer_stage == 4 ||
	    packet->tcp->dest == ntohs(5938) || packet->tcp->source == ntohs(5938)) {
	  ndpi_int_teamview_add_connection(ndpi_struct, flow);
	}
	return;
      }
      else if (flow->teamviewer_stage) {
	if (packet->payload[0] == 0x11 && packet->payload[1] == 0x30) {
	  flow->teamviewer_stage++;
	  if (flow->teamviewer_stage == 4) {
	    ndpi_int_teamview_add_connection(ndpi_struct, flow);
	  }
	}
	return;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_teamviewer_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("TeamViewer", ndpi_struct, *id,
				      NDPI_PROTOCOL_TEAMVIEWER,
				      ndpi_search_teamview,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

