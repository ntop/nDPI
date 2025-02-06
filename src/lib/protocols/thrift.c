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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_APACHE_THRIFT

#include "ndpi_api.h"
#include "ndpi_private.h"

#include <stdint.h>

// References: https://thrift.apache.org AND https://github.com/apache/thrift
// Not Implemented (sub)protocols: TJSONProtocol, TSimpleJSONProtocol and TDebugProtocol

// TBinaryProtocol
PACK_ON
struct thrift_strict_hdr {
  uint8_t protocol_id;
  uint8_t version;
  uint8_t unused_byte_pad;
  uint8_t message_type;
  uint32_t method_length;
  char method[0];
} PACK_OFF;

// TCompactProtocol
PACK_ON
struct thrift_compact_hdr {
  uint8_t protocol_id;
#if defined(__BIG_ENDIAN__)
  uint8_t message_type : 3;
  uint8_t version : 5;
#elif defined(__LITTLE_ENDIAN__)
  uint8_t version : 5;
  uint8_t message_type : 3;
#else
#error "Missing endian macro definitions."
#endif
  uint8_t sequence_id[3];
  uint8_t method_length;
  char method[0];
} PACK_OFF;

enum thrift_message_type {
  TMT_INVALID_TMESSAGE_TYPE = 0,
  TMT_CALL                  = 1,
  TMT_REPLY                 = 2,
  TMT_EXCEPTION             = 3,
  TMT_ONEWAY                = 4,
  TMT_TYPE_MAX
};

static void ndpi_int_thrift_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                           struct ndpi_flow_struct *flow,
                                           uint16_t master_protocol)
{
  switch (master_protocol)
  {
    case NDPI_PROTOCOL_UNKNOWN:
      NDPI_LOG_DBG(ndpi_struct, "found Apache Thrift TCP/UDP\n");
      break;
    case NDPI_PROTOCOL_HTTP:
      NDPI_LOG_DBG(ndpi_struct, "found Apache Thrift HTTP\n");
      break;
  }

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_APACHE_THRIFT, master_protocol,
                             NDPI_CONFIDENCE_DPI);
}

static int thrift_validate_method(char const * const method, size_t method_length)
{
  const union {
    uint8_t const * const ptr;
    char const * const str;
  } m = { .str = method };

  return ndpi_is_printable_buffer(m.ptr, method_length);
}

static int thrift_validate_version(uint8_t version)
{
  return version <= 0x01;
}

static int thrift_validate_type(uint8_t message_type)
{
  return message_type < TMT_TYPE_MAX;
}

static void thrift_set_method(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow,
                              char const * const method, size_t method_length)
{
  if (thrift_validate_method(method, method_length) == 0) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, "Invalid method name");
    flow->protos.thrift.method[0] = '\0';
  } else {
    strncpy(flow->protos.thrift.method, method, ndpi_min(sizeof(flow->protos.thrift.method), method_length));
  }
}

static void thrift_set_type(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow,
                            uint8_t message_type)
{
  if (message_type == TMT_INVALID_TMESSAGE_TYPE) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid message type");
  }
  flow->protos.thrift.message_type = message_type;

  if (message_type == TMT_EXCEPTION) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_ERROR_CODE_DETECTED, "Apache Thrift Exception");
  }
}

static void ndpi_dissect_strict_hdr(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow,
                                    struct thrift_strict_hdr const * const strict_hdr)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  const size_t method_length = ntohl(strict_hdr->method_length);

  if (packet->tcp == NULL) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (packet->payload_packet_len < sizeof(*strict_hdr) + method_length) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (thrift_validate_version(strict_hdr->version) == 0) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (thrift_validate_type(strict_hdr->message_type) == 0) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_thrift_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);

  thrift_set_method(ndpi_struct, flow, strict_hdr->method, method_length);
  thrift_set_type(ndpi_struct, flow, strict_hdr->message_type);
}

static void ndpi_dissect_compact_hdr(struct ndpi_detection_module_struct *ndpi_struct,
                                     struct ndpi_flow_struct *flow,
                                     struct thrift_compact_hdr const * const compact_hdr)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  if (packet->udp == NULL) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (packet->payload_packet_len < sizeof(*compact_hdr) + compact_hdr->method_length) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (thrift_validate_version(compact_hdr->version) == 0) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (thrift_validate_type(compact_hdr->message_type) == 0) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_thrift_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);

  thrift_set_method(ndpi_struct, flow, compact_hdr->method, compact_hdr->method_length);
  thrift_set_type(ndpi_struct, flow, compact_hdr->message_type);
}

static void ndpi_search_thrift_tcp_udp(struct ndpi_detection_module_struct *ndpi_struct,
                                       struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Apache Thrift\n");

  if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
      flow->detected_protocol_stack[1] == NDPI_PROTOCOL_HTTP)
  {
    /* Check Thrift over HTTP */
    if (packet->content_line.ptr != NULL)
    {
      if ((LINE_ENDS(packet->content_line, "application/vnd.apache.thrift.binary") != 0) ||
          (LINE_ENDS(packet->content_line, "application/vnd.apache.thrift.compact") != 0) ||
          (LINE_ENDS(packet->content_line, "application/vnd.apache.thrift.json") != 0))
      {
        NDPI_LOG_INFO(ndpi_struct, "found Apache Thrift over HTTP\n");
        ndpi_int_thrift_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HTTP);
        return;
      }
    }
  } else if (packet->payload_packet_len >= sizeof(struct thrift_compact_hdr)) {
    const union {
      uint8_t const * const raw_ptr;
      struct thrift_strict_hdr const * const strict_hdr;
      struct thrift_compact_hdr const * const compact_hdr;
    } thrift_data = { .raw_ptr = &packet->payload[0] };

    if (thrift_data.raw_ptr[0] == 0x80)
    {
      /* Strict Binary Protocol */
      if (packet->payload_packet_len < sizeof(*thrift_data.strict_hdr))
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }

      ndpi_dissect_strict_hdr(ndpi_struct, flow, thrift_data.strict_hdr);
      return;
    } else if (thrift_data.raw_ptr[0] == 0x82) {
      /* Compact Protocol */
      ndpi_dissect_compact_hdr(ndpi_struct, flow, thrift_data.compact_hdr);
      return;
    } else {
      /* Probably not Apache Thrift. */
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_apache_thrift_dissector(struct ndpi_detection_module_struct *ndpi_struct, uint32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Thrift", ndpi_struct, *id,
                                      NDPI_PROTOCOL_APACHE_THRIFT,
                                      ndpi_search_thrift_tcp_udp,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
