/*
 * ciscovpn.c
 *
 * Copyright (C) 2013-22 - ntop.org
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
 * Dissector developed by Remy Mudingay <mudingay@ill.fr>
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CISCOVPN

#include "ndpi_api.h"

/* ****************************************************************** */

static void ndpi_int_ciscovpn_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CISCOVPN, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* ****************************************************************** */

static void ndpi_search_ciscovpn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t udport = 0, usport = 0;

  NDPI_LOG_DBG(ndpi_struct, "search CISCOVPN\n");

  if(packet->udp != NULL) {
    usport = ntohs(packet->udp->source), udport = ntohs(packet->udp->dest);
    NDPI_LOG_DBG2(ndpi_struct, "calculated CISCOVPN over udp ports\n");
  }

  if(
	  (
	   (usport == 10000 && udport == 10000)
	   &&
	   (packet->payload_packet_len >= 4) &&
	   (packet->payload[0] == 0xfe &&
	    packet->payload[1] == 0x57 &&
	    packet->payload[2] == 0x7e &&
	    packet->payload[3] == 0x2b)
	   )
	  )
    {
      /* This is a good query  fe577e2b */
      NDPI_LOG_INFO(ndpi_struct, "found CISCOVPN\n");
      ndpi_int_ciscovpn_add_connection(ndpi_struct, flow);
      return;
    } 

  if(flow->num_processed_pkts > 5)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_ciscovpn_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("CiscoVPN", ndpi_struct, *id,
				      NDPI_PROTOCOL_CISCOVPN,
				      ndpi_search_ciscovpn,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
