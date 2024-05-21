/*
 * cassandra.c
 *
 * Apache Cassandra CQL Binary protocol
 * 
 * Copyright (C) 2023 - ntop.org
 * Copyright (C) 2023 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CASSANDRA

#include "ndpi_api.h"
#include "ndpi_private.h"

static inline int ndpi_validate_cassandra_response(u_int8_t response)
{
  return (response >= 0x81 && response <= 0x85) ? 1 : -1;
}

static inline int ndpi_validate_cassandra_request(u_int8_t request)
{
  return (request >= 0x01 && request <= 0x05) ? 1 : -1;
}

static void ndpi_int_cassandra_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                              struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Cassandra CQL\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_CASSANDRA, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_cassandra(struct ndpi_detection_module_struct *ndpi_struct,
                                  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Cassandra CQL\n");

  if (packet->payload_packet_len == 19 &&
      ntohl(get_u_int32_t(packet->payload, 0)) == 0xCA552DFA)
  {
    NDPI_LOG_INFO(ndpi_struct, "found Cassandra Internode Communication\n");
    ndpi_int_cassandra_add_connection(ndpi_struct, flow);
    return;
  }

  if ((packet->payload_packet_len < 9) ||
      (flow->packet_counter >= 8) ||
      (!ndpi_validate_cassandra_response(packet->payload[0]) ||
       !ndpi_validate_cassandra_request(packet->payload[0])))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  
  if (flow->packet_direction_counter[packet->packet_direction] > 2) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  
  /* Looking for a 'STARTUP' message from the client,
   * which should always contain the CQL_VERSION string
   */
  if (packet->payload_packet_len > 60 &&
      memcmp(&packet->payload[packet->payload_packet_len-20], "CQL_VERSION", 11) == 0)
  {
    NDPI_LOG_INFO(ndpi_struct, "found Cassandra CQL\n");
    ndpi_int_cassandra_add_connection(ndpi_struct, flow);
    return;
  }
}

void init_cassandra_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                              u_int32_t *id) {

  ndpi_set_bitmask_protocol_detection("Cassandra",
                                      ndpi_struct,
                                      *id,
                                      NDPI_PROTOCOL_CASSANDRA,
                                      ndpi_search_cassandra,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
