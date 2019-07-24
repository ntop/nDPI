/*
 * targus_getdata.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TARGUS_GETDATA

#include "ndpi_api.h"

static void ndpi_check_targus_getdata(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->iph) {
    u_int16_t targus_getdata_port       = ntohs(5201);
    u_int16_t complex_link_port         = ntohs(5001);

    if(((packet->tcp != NULL) && ((packet->tcp->dest == targus_getdata_port)
                             || (packet->tcp->source == targus_getdata_port)
                             || (packet->tcp->dest == complex_link_port)
                             || (packet->tcp->source == complex_link_port)))
      || ((packet->udp != NULL) && ((packet->udp->dest == targus_getdata_port)
                                || (packet->udp->source == targus_getdata_port)
                                || (packet->udp->dest == complex_link_port)
                                || (packet->udp->source == complex_link_port)))) {

      NDPI_LOG_INFO(ndpi_struct, "found targus getdata used for speedtest\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TARGUS_GETDATA, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void ndpi_search_targus_getdata(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search targus getdata\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_TARGUS_GETDATA)
    ndpi_check_targus_getdata(ndpi_struct, flow);
}


void init_targus_getdata_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("TARGUS_GETDATA", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_TARGUS_GETDATA,
				      ndpi_search_targus_getdata,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
