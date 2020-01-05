/*
 * dhcpv6.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DHCPV6

#include "ndpi_api.h"


static void ndpi_int_dhcpv6_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow)
{

  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DHCPV6, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_dhcpv6_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG_DBG(ndpi_struct, "search DHCPv6\n");

	if (packet->payload_packet_len >= 4 &&
		(packet->udp->source == htons(546) || packet->udp->source == htons(547)) &&
		(packet->udp->dest == htons(546) || packet->udp->dest == htons(547)) &&
		packet->payload[0] >= 1 && packet->payload[0] <= 13) {

		NDPI_LOG_INFO(ndpi_struct, "found DHCPv6\n");
		ndpi_int_dhcpv6_add_connection(ndpi_struct, flow);
		return;
	}

	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_dhcpv6_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("DHCPV6", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DHCPV6,
				      ndpi_search_dhcpv6_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
