/*
 * kerberos.c
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

#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_KERBEROS

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_KERBEROS

#include "ndpi_api.h"


static void ndpi_int_kerberos_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					     struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_KERBEROS, NDPI_PROTOCOL_UNKNOWN);
  NDPI_LOG_DBG(ndpi_struct, "trace KERBEROS\n");
}


void ndpi_search_kerberos(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG_DBG(ndpi_struct, "search KERBEROS\n");

	/* I have observed 0a,0c,0d,0e at packet->payload[19/21], maybe there are other possibilities */
	if (packet->payload_packet_len >= 4 && ntohl(get_u_int32_t(packet->payload, 0)) == packet->payload_packet_len - 4) {
		if (packet->payload_packet_len > 19 &&
			packet->payload[14] == 0x05 &&
			(packet->payload[19] == 0x0a ||
			 packet->payload[19] == 0x0c || packet->payload[19] == 0x0d || packet->payload[19] == 0x0e)) {
			ndpi_int_kerberos_add_connection(ndpi_struct, flow);
			return;

		}
		if (packet->payload_packet_len > 21 &&
			packet->payload[16] == 0x05 &&
			(packet->payload[21] == 0x0a ||
			 packet->payload[21] == 0x0c || packet->payload[21] == 0x0d || packet->payload[21] == 0x0e)) {
			ndpi_int_kerberos_add_connection(ndpi_struct, flow);
			return;

		}
	}
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_kerberos_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Kerberos", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_KERBEROS,
				      ndpi_search_kerberos,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
