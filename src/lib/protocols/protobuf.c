/*
 * protobuf.c
 *
 * Copyright (C) 2023 by ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_PROTOBUF
//#define DEBUG_PROTOBUF 1
#define PROTOBUF_MIN_ELEMENTS 2
#define PROTOBUF_MAX_ELEMENTS 32
#define PROTOBUF_REQUIRED_ELEMENTS 8
#define PROTOBUF_MIN_PACKETS 4
#define PROTOBUF_MAX_PACKETS 8

#include "ndpi_api.h"
#include "ndpi_private.h"

enum protobuf_type {
  PT_INVALID = -1,
  PT_VARINT = 0,
  PT_I64,
  PT_LEN,
  PT_SGROUP, // deprecated
  PT_EGROUP, // deprecated
  PT_I32
};

size_t protobuf_dissect(unsigned char const * const buffer, size_t const size,
                        size_t * const protobuf_elements,
                        size_t * const protobuf_len_elements);

static void ndpi_int_protobuf_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                             struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Protobuf\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PROTOBUF, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static enum protobuf_type
protobuf_dissect_tag(uint64_t tag, uint64_t * const field_number)
{
  uint8_t const wire_type = tag & 0x07;
  *field_number = tag >> 3;

  switch (wire_type)
  {
    case PT_VARINT:
    case PT_I64:
    case PT_LEN:
    case PT_SGROUP:
    case PT_EGROUP:
    case PT_I32:
      return wire_type;
  }

  return PT_INVALID;
}

static int
protobuf_dissect_varint(unsigned char const * const buffer, size_t size,
                        size_t * const offset, uint64_t * const value)
{
  size_t i;
  *value = 0;

  for (i = 0; i < 9; ++i)
  {
    if (size < *offset + i + 1)
    {
      return -1;
    }

    *value |= ((uint64_t)(buffer[*offset + i] & 0x7F)) << (i * 8 - i);
    if ((buffer[*offset + i] & 0x80) == 0)
    {
      break;
    }
  }

  *offset += i + 1;
  return 0;
}

size_t protobuf_dissect(unsigned char const * const buffer, size_t const size,
                        size_t * const protobuf_elements,
                        size_t * const protobuf_len_elements)
{
  *protobuf_elements = 0;
  *protobuf_len_elements = 0;
  size_t offset = 0;

#ifdef DEBUG_PROTOBUF
  printf("Protobuf:");
#endif
  do {
#ifdef DEBUG_PROTOBUF
    printf(" ");
#endif
    uint64_t tag;
    // A Protobuf tag has a type and a field number stored as u32 varint.
    if (protobuf_dissect_varint(buffer, size, &offset, &tag) != 0)
    {
      break;
    }

    uint64_t field_number;
    enum protobuf_type type = protobuf_dissect_tag(tag, &field_number);
    if (type == PT_INVALID || field_number == 0 || field_number > (UINT_MAX >> 3))
    {
      return 0;
    }

#ifdef DEBUG_PROTOBUF
    printf("[id: %llu]", (unsigned long long int)field_number);
#endif
    switch (type)
    {
      case PT_VARINT:
      {
        uint64_t value;
        if (protobuf_dissect_varint(buffer, size, &offset, &value) != 0)
        {
          return 0;
        }
#ifdef DEBUG_PROTOBUF
        printf("[VARINT: %llu / %llx]", (unsigned long long int)value,
               (unsigned long long int)value);
#endif
        break;
      }
      case PT_I64: {
        if (size < offset + sizeof(uint64_t))
        {
          return 0;
        }
#ifdef DEBUG_PROTOBUF
        union {
          int64_t as_i64;
          uint64_t as_u64;
          double as_double;
        } value;
        value.as_u64 = le64toh(*(uint64_t *)&buffer[offset]);
        printf("[I64: %lld / %llu / %lf]", (long long int)value.as_i64,
               (unsigned long long int)value.as_u64, value.as_double);
#endif
        offset += 8;
        break;
      }
      case PT_LEN:
      {
        uint64_t length;
        if (protobuf_dissect_varint(buffer, size, &offset, &length) != 0)
        {
          if (size >= offset)
          {
            break; // We are not excluding the protocol immediately. Let's wait for more packets to arrive..
          } else {
            return 0;
          }
        }
        if (length == 0 || length > INT_MAX)
        {
          return 0;
        }
        offset += length;
        (*protobuf_len_elements)++;
#ifdef DEBUG_PROTOBUF
        printf("[LEN length: %llu]", (unsigned long long int)length);
#endif
        break;
      }
      case PT_SGROUP:
      case PT_EGROUP:
        // Start/End groups are deprecated and therefor ignored to reduce false positives.
        return 0;
      case PT_I32: {
        if (size < offset + sizeof(uint32_t))
        {
          return 0;
        }
#ifdef DEBUG_PROTOBUF
        union {
          int32_t as_i32;
          uint32_t as_u32;
          float as_float;
        } value;
        value.as_u32 = le32toh(*(uint32_t *)&buffer[offset]);
        printf("[I32: %d / %u / %f]", value.as_i32, value.as_u32, value.as_float);
#endif
        offset += 4;
        break;
      }
      case PT_INVALID:
        break;
    }
  } while (++(*protobuf_elements) < PROTOBUF_MAX_ELEMENTS);

#ifdef DEBUG_PROTOBUF
  printf(" [offset: %llu][length: %zu][elems: %llu][len_elems: %llu]\n",
         (unsigned long long int)offset, size,
         (unsigned long long int)protobuf_elements,
         (unsigned long long int)protobuf_len_elements);
#endif
  return offset;
}

static void ndpi_search_protobuf(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Protobuf\n");

  size_t protobuf_elements = 0;
  size_t protobuf_len_elements = 0;
  size_t bytes_parsed = protobuf_dissect(packet->payload, packet->payload_packet_len,
                                         &protobuf_elements, &protobuf_len_elements);

  if (bytes_parsed == 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if ((protobuf_elements >= PROTOBUF_REQUIRED_ELEMENTS && protobuf_len_elements > 0 &&
       /* (On UDP) this packet might be also a RTP/RTCP one. Wait for the next one */
       (flow->packet_counter > 1 || flow->l4_proto == IPPROTO_TCP || flow->rtp_stage == 0))
      || (flow->packet_counter >= PROTOBUF_MIN_PACKETS && protobuf_elements >= PROTOBUF_MIN_ELEMENTS))
  {
#ifdef DEBUG_PROTOBUF
    printf("Protobuf found after %u packets.\n", flow->packet_counter);
#endif
    ndpi_int_protobuf_add_connection(ndpi_struct, flow);
    return;
  }

  if (packet->payload_packet_len >= bytes_parsed
      && protobuf_elements > 0
      && flow->packet_counter <= PROTOBUF_MAX_PACKETS)
  {
    return; // We probably need more packets to dissect.
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}


void init_protobuf_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Protobuf", ndpi_struct,
                     ndpi_search_protobuf,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_PROTOBUF);
}
