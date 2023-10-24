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
//#define DEBUG_PROTOBUF
#define PROTOBUF_MIN_ELEMENTS 2
#define PROTOBUF_MAX_ELEMENTS 8
#define PROTOBUF_MIN_PACKETS 4
#define PROTOBUF_MAX_PACKETS 8

#include "ndpi_api.h"

enum protobuf_tag {
  TAG_INVALID = -1,
  TAG_VARINT = 0,
  TAG_I64,
  TAG_LEN,
  TAG_SGROUP, // deprecated
  TAG_EGROUP, // deprecated
  TAG_I32
};

static void ndpi_int_protobuf_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                             struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Protobuf\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PROTOBUF, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static enum protobuf_tag
protobuf_dissect_wire_type(struct ndpi_packet_struct const * const packet,
                           size_t * const offset,
                           uint8_t * const field_number)
{
  if (packet->payload_packet_len < *offset + 1)
  {
    return TAG_INVALID;
  }

  uint8_t const wire_type = packet->payload[*offset] & 0x07; // field number ignored
  *field_number = packet->payload[*offset] >> 3;

  switch (wire_type)
  {
    case TAG_VARINT:
    case TAG_I64:
    case TAG_LEN:
    case TAG_SGROUP:
    case TAG_EGROUP:
    case TAG_I32:
      (*offset)++;
      return wire_type;
  }

  return TAG_INVALID;
}

static int
protobuf_dissect_varint(struct ndpi_packet_struct const * const packet,
                        size_t * const offset, uint64_t * const value)
{
  size_t i;
  *value = 0;

  for (i = 0; i < 9; ++i)
  {
    if (packet->payload_packet_len < *offset + i + 1)
    {
      return -1;
    }

    *value |= ((uint64_t)(packet->payload[*offset + i] & 0x7F)) << (i * 8 - i);
    if ((packet->payload[*offset + i] & 0x80) == 0)
    {
      break;
    }
  }

  if (i == 10)
  {
    return -1;
  }

  *offset += i + 1;
  return 0;
}

static int protobuf_validate_field_number(uint32_t * const saved_field_numbers,
                                          uint8_t field_number,
                                          enum protobuf_tag tag)
{
  uint32_t shifted_field_number;

  if (field_number > 31 || field_number == 0)
  {
    return -1;
  }

  shifted_field_number = 1u << (field_number - 1);
  if (tag != TAG_LEN
      && (*saved_field_numbers & shifted_field_number) != 0)
  {
    return -1;
  }

  *saved_field_numbers |= shifted_field_number;
  return 0;
}

static void ndpi_search_protobuf(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Protobuf\n");

  uint32_t field_numbers_used = 0;
  size_t protobuf_elements = 0;
  size_t protobuf_len_elements = 0;
  size_t offset = 0;

#ifdef DEBUG_PROTOBUF
  printf("Protobuf:");
#endif
  do {
#ifdef DEBUG_PROTOBUF
    printf(" ");
#endif
    uint8_t field_number;
    enum protobuf_tag tag = protobuf_dissect_wire_type(packet, &offset,
                                                       &field_number);
    if (tag == TAG_INVALID)
    {
      break;
    }
    if (protobuf_validate_field_number(&field_numbers_used, field_number,
                                       tag) != 0)
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

#ifdef DEBUG_PROTOBUF
    printf("[id: %u]", field_number);
#endif
    switch (tag)
    {
      case TAG_VARINT:
      {
        uint64_t value;
        if (protobuf_dissect_varint(packet, &offset, &value) != 0)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
#ifdef DEBUG_PROTOBUF
        printf("[VARINT: %llu]", (unsigned long long int)value);
#endif
        break;
      }
      case TAG_I64: {
        if (packet->payload_packet_len < offset + sizeof(uint64_t))
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
#ifdef DEBUG_PROTOBUF
        uint64_t value = ndpi_ntohll(*(uint64_t *)&packet->payload[offset]);
        printf("[I64: %llu]", (unsigned long long int)value);
#endif
        offset += 8;
        break;
      }
      case TAG_LEN:
      case TAG_SGROUP:
      case TAG_EGROUP:
      {
        uint64_t length;
        if (protobuf_dissect_varint(packet, &offset, &length) != 0)
        {
          if (packet->payload_packet_len >= offset)
          {
            break; // We are not excluding the protocol immediately. Let's wait for more packets to arrive..
          } else {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }
        }
        if (length == 0 || length > INT_MAX)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
        offset += length;
        protobuf_len_elements++;
#ifdef DEBUG_PROTOBUF
        printf("[LEN/SGROUP/EGROUP length: %llu]", (unsigned long long int)length);
#endif
        break;
      }
      case TAG_I32: {
        if (packet->payload_packet_len < offset + sizeof(uint32_t))
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          break;
        }
#ifdef DEBUG_PROTOBUF
        uint32_t value = ntohl(*(uint32_t *)&packet->payload[offset]);
        printf("[I32: %u]", value);
#endif
        offset += 4;
        break;
      }
      case TAG_INVALID:
        break;
    }
  } while (++protobuf_elements < PROTOBUF_MAX_ELEMENTS);

#ifdef DEBUG_PROTOBUF
  printf("\n");
#endif
  if ((protobuf_elements == PROTOBUF_MAX_ELEMENTS && protobuf_len_elements > 0)
      || (flow->packet_counter >= PROTOBUF_MIN_PACKETS && protobuf_elements >= PROTOBUF_MIN_ELEMENTS))
  {
    ndpi_int_protobuf_add_connection(ndpi_struct, flow);
    return;
  }

  if (packet->payload_packet_len >= offset
      && protobuf_elements > 0
      && flow->packet_counter <= PROTOBUF_MAX_PACKETS)
  {
    return; // We probably need more packets to dissect.
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_protobuf_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                             u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Protobuf", ndpi_struct, *id,
                                      NDPI_PROTOCOL_PROTOBUF,
                                      ndpi_search_protobuf,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
