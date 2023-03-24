/*
 * thrift.c
 *
 * Copyright (C) 2023 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_THRIFT

#include "ndpi_api.h"

#define THRIFT_BINARY_VERSION_MASK	0xFFFF00F8
#define THRIFT_COMPACT_VERSION_MASK	0xFF1F
#define THRIFT_BINARY_MESSAGE_MASK	0x00000007
#define THRIFT_COMPACT_MESSAGE_MASK	0x00E0
#define THRIFT_BINARY_VERSION_1		0x80010000
#define THRIFT_COMPACT_VERSION_1	0x8201

typedef enum
{
    T_CALL = 1,
    T_REPLY,
    T_EXCEPTION,
    T_ONEWAY
} ndpi_thrift_method_type;

static int ndpi_check_is_thrift_strict(u_int32_t thrift_strict_header)
{
    if ((thrift_strict_header & THRIFT_BINARY_VERSION_MASK) != 
				THRIFT_BINARY_VERSION_1)
    {
	return -1;
    }

    u_int8_t thrift_msg_type = (thrift_strict_header & THRIFT_BINARY_MESSAGE_MASK);

    if ((thrift_msg_type >= T_CALL) && (thrift_msg_type <= T_ONEWAY))
    {
	return 1;
    }

    return -1;
}

static int ndpi_check_is_thrift_compact(u_int16_t thrift_compact_header)
{
    if ((thrift_compact_header & THRIFT_COMPACT_VERSION_MASK) != 
				 THRIFT_COMPACT_VERSION_1)
    {
	return -1;
    }

    u_int8_t thrift_msg_type = (thrift_compact_header & THRIFT_COMPACT_MESSAGE_MASK) >> 5;

    if ((thrift_msg_type >= T_CALL) && (thrift_msg_type <= T_ONEWAY))
    {
	return 1;
    }

    return -1;
}

static void ndpi_int_thrift_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
					   struct ndpi_flow_struct *flow)
{
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_THRIFT, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_thrift_tcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &ndpi_struct->packet;

    if (packet->payload_packet_len > 5)
    {
	/* Check Thrift over HTTP */
	if (packet->content_line.ptr != NULL)
	{
	    if ((LINE_ENDS(packet->content_line, "application/vnd.apache.thrift.binary") != 0) || 
		(LINE_ENDS(packet->content_line, "application/vnd.apache.thrift.compact") != 0) ||
		(LINE_ENDS(packet->content_line, "application/vnd.apache.thrift.json") != 0))
	    {
		NDPI_LOG_INFO(ndpi_struct, "found Apache Thrift over HTTP\n");
		ndpi_int_thrift_add_connection(ndpi_struct, flow);
		return;
	    }
	}

	/* Is it old binary version? */
	if (ndpi_check_is_thrift_strict(ntohl(get_u_int32_t(packet->payload, 0))))
	{
	    NDPI_LOG_INFO(ndpi_struct, "found Apache Thrift: old binary protocol\n");
	    ndpi_int_thrift_add_connection(ndpi_struct, flow);
	    return;
	}

	/* Well, may be it's newer compact version? */
	if (ndpi_check_is_thrift_compact(ntohs(get_u_int16_t(packet->payload, 0))))
	{
	    NDPI_LOG_INFO(ndpi_struct, "found Apache Thrift: newer compact protocol\n");
	    ndpi_int_thrift_add_connection(ndpi_struct, flow);
	    return;
	}
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_thrift_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
    ndpi_set_bitmask_protocol_detection("Thrift", ndpi_struct, *id,
					NDPI_PROTOCOL_THRIFT,
					ndpi_search_thrift_tcp_udp,
					NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
					SAVE_DETECTION_BITMASK_AS_UNKNOWN,
					ADD_TO_DETECTION_BITMASK);
    *id += 1;
}
