/*
 * cassandra.c
 *
 * Copyright (C) 2021 by Lucas Santos <lfneiva.santos@gmail.com>
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
 */

#include <stdbool.h>
#include "ndpi_protocol_ids.h"
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CASSANDRA
#include "ndpi_api.h"

#define CASSANDRA_HEADER_LEN 9
#define CASSANDRA_MAX_BODY_SIZE 268435456 //256MB (256 * 1024^2)

enum cassandra_version
{
  CASSANDRA_V1_REQUEST = 0x01,
  CASSANDRA_V1_RESPONSE = 0x81,
  CASSANDRA_V2_REQUEST = 0x02,
  CASSANDRA_V2_RESPONSE = 0x82,
  CASSANDRA_V3_REQUEST = 0x03,
  CASSANDRA_V3_RESPONSE = 0x83,
  CASSANDRA_V4_REQUEST = 0x04,
  CASSANDRA_V4_RESPONSE = 0x84
};

enum cassandra_opcode
{
  CASSANDRA_ERROR = 0x00,
  CASSANDRA_STARTUP = 0x01,
  CASSANDRA_READY = 0x02,
  CASSANDRA_AUTHENTICATE = 0x03,
  CASSANDRA_OPTIONS = 0x05,
  CASSANDRA_SUPPORTED = 0x06,
  CASSANDRA_QUERY = 0x07,
  CASSANDRA_RESULT = 0x08,
  CASSANDRA_PREPARE = 0x09,
  CASSANDRA_EXECUTE = 0x0A,
  CASSANDRA_REGISTER = 0x0B,
  CASSANDRA_EVENT = 0x0C,
  CASSANDRA_BATCH = 0x0D,
  CASSANDRA_AUTH_CHALLENGE = 0x0E,
  CASSANDRA_AUTH_RESPONSE = 0x0F,
  CASSANDRA_AUTH_SUCCESS = 0x10
};

static bool ndpi_check_valid_cassandra_version(uint8_t version)
{
  switch(version) {
    case CASSANDRA_V1_REQUEST:
    case CASSANDRA_V1_RESPONSE:
    case CASSANDRA_V2_REQUEST:
    case CASSANDRA_V2_RESPONSE:
    case CASSANDRA_V3_REQUEST:
    case CASSANDRA_V3_RESPONSE:
    case CASSANDRA_V4_REQUEST:
    case CASSANDRA_V4_RESPONSE:
      return true;
  }
  return false;
}

static bool ndpi_check_valid_cassandra_opcode(uint8_t opcode)
{
  switch (opcode) {
    case CASSANDRA_ERROR:
    case CASSANDRA_STARTUP:
    case CASSANDRA_READY:
    case CASSANDRA_AUTHENTICATE:
    case CASSANDRA_OPTIONS:
    case CASSANDRA_SUPPORTED:
    case CASSANDRA_QUERY:
    case CASSANDRA_RESULT:
    case CASSANDRA_PREPARE:
    case CASSANDRA_EXECUTE:
    case CASSANDRA_REGISTER:
    case CASSANDRA_EVENT:
    case CASSANDRA_BATCH:
    case CASSANDRA_AUTH_CHALLENGE:
    case CASSANDRA_AUTH_RESPONSE:
    case CASSANDRA_AUTH_SUCCESS:
      return true;
  }
  return false;
}

static bool ndpi_check_valid_cassandra_flags(uint8_t flags)
{
  return (flags & 0xF0) == 0;
}

void ndpi_search_cassandra(struct ndpi_detection_module_struct *ndpi_struct,
                           struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if (packet->tcp) {
    if (packet->payload_packet_len >= CASSANDRA_HEADER_LEN &&
        ndpi_check_valid_cassandra_version(get_u_int8_t(packet->payload, 0)) &&
        ndpi_check_valid_cassandra_flags(get_u_int8_t(packet->payload, 1)) &&
        ndpi_check_valid_cassandra_opcode(get_u_int8_t(packet->payload, 4)) &&
        le32toh(get_u_int32_t(packet->payload, 5)) <= CASSANDRA_MAX_BODY_SIZE &&
        le32toh(get_u_int32_t(packet->payload, 5)) >= (uint32_t) (packet->payload_packet_len - CASSANDRA_HEADER_LEN)) {
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CASSANDRA, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ********************************* */


void init_cassandra_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                              u_int32_t *id,
                              NDPI_PROTOCOL_BITMASK *detection_bitmask) {

  ndpi_set_bitmask_protocol_detection("Cassandra",
                                      ndpi_struct, detection_bitmask,
                                      *id,
                                      NDPI_PROTOCOL_CASSANDRA,
                                      ndpi_search_cassandra,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
