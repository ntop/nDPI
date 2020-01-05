/*
 * nest_log_sink.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-20 - ntop.org
 * Copyright (C) 2018 - eGloo Incorporated
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

#define NDPI_CURRENT_PROTO      NDPI_PROTOCOL_NEST_LOG_SINK

#include "ndpi_api.h"

#define NEST_LOG_SINK_PORT          11095
#define NEST_LOG_SINK_MIN_LEN       8
#define NEST_LOG_SINK_MIN_MATCH     3

void ndpi_search_nest_log_sink(
        struct ndpi_detection_module_struct *ndpi_struct,
        struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;

    NDPI_LOG_DBG(ndpi_struct, "search nest_log_sink\n");

    if (packet->payload_packet_len < NEST_LOG_SINK_MIN_LEN) {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
    }

    if (ntohs(packet->tcp->source) != NEST_LOG_SINK_PORT &&
            ntohs(packet->tcp->dest) != NEST_LOG_SINK_PORT) {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
    }

    if (packet->payload[1] <= 0x02 &&
            (packet->payload[2] == 0x00 || packet->payload[2] == 0x10) &&
            packet->payload[3] == 0x13)
        flow->l4.tcp.nest_log_sink_matches++;

    if (flow->l4.tcp.nest_log_sink_matches == NEST_LOG_SINK_MIN_MATCH) {
        NDPI_LOG_INFO(ndpi_struct, "found nest_log_sink\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NEST_LOG_SINK, NDPI_PROTOCOL_UNKNOWN);
    }
}

void init_nest_log_sink_dissector(
        struct ndpi_detection_module_struct *ndpi_struct,
        u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
    ndpi_set_bitmask_protocol_detection("NEST_LOG_SINK",
            ndpi_struct, detection_bitmask, *id,
            NDPI_PROTOCOL_NEST_LOG_SINK,
            ndpi_search_nest_log_sink,
            NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
            SAVE_DETECTION_BITMASK_AS_UNKNOWN,
            ADD_TO_DETECTION_BITMASK);

    *id += 1;
}
