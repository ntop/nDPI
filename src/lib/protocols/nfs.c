/*
 * nfs.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NFS

#include "ndpi_api.h"


static void ndpi_int_nfs_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NFS, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_nfs(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG_DBG(ndpi_struct, "search NFS\n");

	u_int8_t offset = 0;
	if (packet->tcp != NULL)
		offset = 4;

	if (packet->payload_packet_len < (40 + offset))
		goto exclude_nfs;

	NDPI_LOG_DBG2(ndpi_struct, "NFS user match stage 1\n");


	if (offset != 0 && get_u_int32_t(packet->payload, 0) != htonl(0x80000000 + packet->payload_packet_len - 4))
		goto exclude_nfs;

	NDPI_LOG_DBG2(ndpi_struct, "NFS user match stage 2\n");

	if (get_u_int32_t(packet->payload, 4 + offset) != 0)
		goto exclude_nfs;

	NDPI_LOG_DBG2(ndpi_struct, "NFS user match stage 3\n");

	if (get_u_int32_t(packet->payload, 8 + offset) != htonl(0x02))
		goto exclude_nfs;

	NDPI_LOG_DBG2(ndpi_struct, "NFS match stage 3\n");

	if (get_u_int32_t(packet->payload, 12 + offset) != htonl(0x000186a5)
		&& get_u_int32_t(packet->payload, 12 + offset) != htonl(0x000186a3)
		&& get_u_int32_t(packet->payload, 12 + offset) != htonl(0x000186a0))
		goto exclude_nfs;

	NDPI_LOG_DBG2(ndpi_struct, "NFS match stage 4\n");

	if (ntohl(get_u_int32_t(packet->payload, 16 + offset)) > 4)
		goto exclude_nfs;

	NDPI_LOG_INFO(ndpi_struct, "found NFS\n");

	ndpi_int_nfs_add_connection(ndpi_struct, flow);
	return;

  exclude_nfs:
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_nfs_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("NFS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_NFS,
				      ndpi_search_nfs,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

