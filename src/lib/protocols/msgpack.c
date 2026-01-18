/*
 * msgpack.c
 *
 * Copyright (C) 2011-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MSGPACK

#include "ndpi_api.h"
#include "ndpi_private.h"

#define MSGPACK_MAX_OBJECTS 32
#define MSGPACK_MAX_PACKETS 4

static void ndpi_int_msgpack_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                            struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found MessagePack\n");
  if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
    ndpi_set_detected_protocol_keeping_master(ndpi_struct, flow, NDPI_PROTOCOL_MSGPACK, NDPI_CONFIDENCE_DPI);
  } else {
    ndpi_set_detected_protocol(ndpi_struct, flow,
                               NDPI_PROTOCOL_MSGPACK,
                               NDPI_PROTOCOL_UNKNOWN,
                               NDPI_CONFIDENCE_DPI);
  }
}

static u_int32_t msgpack_dissect_next(u_int8_t const ** const start,
                                      u_int16_t * const size,
                                      u_int8_t * const fb)
{
  if (*size == 0)
    return 0;

  u_int32_t next_size = 0;
  u_int8_t first_byte = *fb = (*start)[0];

  // unused
  if (first_byte == 0xC1)
    return 0;

  /*
   * 1. positive fixint (MSB is zero)
   * 2. negative fixint (three consecutive bits set starting with the MSB)
   * 3. nil
   * 4. false / true
   */
  if ((first_byte & 0x80  /* 0xxx xxxx */) == 0 ||
      (first_byte & 0xE0  /* 111x xxxx */) == 0xE0 ||
      (first_byte == 0xC0 /* 1100 0000 */) ||
      (first_byte & 0xFE  /* 1100 001x */) == 0xC2)
  {
    (*start)++;
    (*size)--;
    return 1;
  }

  if (first_byte == 0xCC /* uint8 */ ||
      first_byte == 0xD0 /* int8 */)
  {
    next_size += 2;
  }
  else if (first_byte == 0xCD /* uint16 */ ||
           first_byte == 0xD1 /* int16 */)
  {
    next_size += 3;
  }
  else if (first_byte == 0xCE /* uint32 */ ||
           first_byte == 0xD2 /* int32 */ ||
           first_byte == 0xCE /* float32 aka float */)
  {
    next_size += 5;
  }
  else if (first_byte == 0xCF /* uint64 */ ||
           first_byte == 0xD3 /* int64 */ ||
           first_byte == 0xCB /* float64 aka double */)
  {
    next_size += 9;
  }
  // ext format
  else if (first_byte == 0xD4 /* fixext1 */)
  {
    next_size += 3;
  }
  else if (first_byte == 0xD5 /* fixext2 */)
  {
    next_size += 4;
  }
  else if (first_byte == 0xD6 /* fixext4 / timestamp32 */)
  {
    next_size += 6;
  }
  else if (first_byte == 0xD7 /* fixext8 / timestamp64 */)
  {
    next_size += 10;
  }
  else if (first_byte == 0xD8 /* fixext16 */)
  {
    next_size += 18;
  }
  else if (first_byte == 0xC7 /* ext8 / timestamp96 */)
  {
    if (*size < 3)
      return 0;
    next_size += 3 + get_u_int8_t(*start, 1);
    if (next_size < 3) // check for possible overflow
      return 0;
  }
  else if (first_byte == 0xC8 /* ext16 */)
  {
    if (*size < 4)
      return 0;
    next_size += 4 + ntohs(get_u_int16_t(*start, 1));
    if (next_size < 4) // check for possible overflow
      return 0;
  }
  else if (first_byte == 0xC9 /* ext32 */)
  {
    if (*size < 6)
      return 0;
    next_size += 6 + ntohl(get_u_int32_t(*start, 1));
    if (next_size < 6) // check for possible overflow
      return 0;
  }
  // map / array / string / bin format
  else if ((first_byte & 0xF0) == 0x80 /* fixmap: 1000 xxxx */ ||
           (first_byte & 0xF0) == 0x90 /* fixarray: 1001 xxxx */)
  {
    next_size++; // (probably) more to dissect
  }
  else if ((first_byte & 0xE0) == 0xA0 /* fixstr: 101x xxxx */)
  {
    next_size += 1 + (first_byte & 0x1F);
    if (next_size < 1) // check for possible overflow
      return 0;
  }
  else if (first_byte == 0xDE /* map16 */ ||
           first_byte == 0xDC /* array16 */)
  {
    next_size += 3; // (probably) more to dissect
  }
  else if (first_byte == 0xDF /* map32 */ ||
           first_byte == 0xDD /* array32 */)
  {
    next_size += 5; // (probably) more to dissect
  }
  else if (first_byte == 0xD9 /* str8 */ ||
           first_byte == 0xC4 /* bin8 */)
  {
    if (*size < 2)
      return 0;
    next_size += 2 + get_u_int8_t(*start, 1);
    if (next_size < 2) // check for possible overflow
      return 0;
  }
  else if (first_byte == 0xDA /* str16 */ ||
           first_byte == 0xC5 /* bin16 */)
  {
    if (*size < 3)
      return 0;
    next_size += 3 + ntohs(get_u_int16_t(*start, 1));
    if (next_size < 3) // check for possible overflow
      return 0;
  }
  else if (first_byte == 0xDB /* str32 */ ||
           first_byte == 0xC6 /* bin32 */)
  {
    if (*size < 5)
      return 0;
    next_size += 5 + ntohl(get_u_int32_t(*start, 1));
    if (next_size < 5) // check for possible overflow
      return 0;
  }

  if (next_size == 0)
    return 0;
  if (next_size > *size)
    return 0;

  // check for valid UTF-8 / ASCII strings
  char const * str = NULL;
  u_int32_t str_len = 0;
  if ((first_byte & 0xE0) == 0xA0 /* fixstr */) {
    str = (const char *)(*start + 1);
    str_len = next_size - 1;
  }
  else if (first_byte == 0xD9 /* str8 */)
  {
    str = (const char *)(*start + 2);
    str_len = next_size - 2;
  }
  else if (first_byte == 0xDA /* str16 */)
  {
    str = (const char *)(*start + 3);
    str_len = next_size - 3;
  }
  else if (first_byte == 0xDB /* str32 */)
  {
    str = (const char *)(*start + 5);
    str_len = next_size - 5;
  }
  if (str != NULL && str_len > 0) {
    u_int32_t i;
    for (i = 0; i < str_len; ++i) {
      if (isascii(str[i]) != 0 && ndpi_isprint(str[i]) == 0 && ndpi_isspace(str[i]) == 0)
        return 0;
    }
  }

  (*start) += next_size;
  (*size) -= next_size;
  return next_size;
}

void ndpi_search_msgpack(struct ndpi_detection_module_struct *ndpi_struct,
                         struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search MessagePack\n");

  u_int8_t const * cur_msg = &packet->payload[0];
  u_int16_t rem_siz = packet->payload_packet_len;
  u_int16_t msgpack_objects = 0;
  u_int16_t byte_type_objects = 0; // required to prevent false positives due to fixint's
  u_int16_t tlv_objects = 0;

  do {
    u_int8_t first_byte = 0xC1;
    u_int32_t type_size = msgpack_dissect_next(&cur_msg, &rem_siz, &first_byte);
    if (type_size == 0 || first_byte == 0xC1)
      break;
    if (type_size == 1) {
      // fixmap's and fixarray's get also counted as byte type objects..
      if ((first_byte & 0xF0) != 0x80 /* fixmap: 1000 xxxx */ &&
          (first_byte & 0xF0) != 0x90 /* fixarray: 1001 xxxx */)
      {
        byte_type_objects++;
      }
    }
    if (type_size >= 2) {
      // check for variable sized ext's / str's / bin's
      if ((first_byte >= 0xC4 && first_byte <= 0xC9 /* bin8, bin16, bin32, ext8, ext16, ext32 */)
          || (first_byte & 0xE0) == 0xA0 /* fixstr */
          || (first_byte >= 0xD9 && first_byte <= 0xDB /* str8, str16, str32 */))
      {
        tlv_objects++;
      }
    }
  } while (++msgpack_objects < MSGPACK_MAX_OBJECTS);

  NDPI_LOG_DBG(ndpi_struct, " [Objects: %u][ByteTypes: %u][TLVs: %u][Remaining: %u][Length %u]\n",
               msgpack_objects, byte_type_objects, tlv_objects, rem_siz, packet->payload_packet_len);

  if (byte_type_objects * 2 >= msgpack_objects ||
      rem_siz * 4 >= packet->payload_packet_len)
  {
    if (rem_siz > 0 || flow->packet_counter >= MSGPACK_MAX_PACKETS)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if ((rem_siz == 0 && flow->packet_counter > 1) || tlv_objects > 0
      || (byte_type_objects * 4 < msgpack_objects && packet->tcp != NULL))
  {
    ndpi_int_msgpack_add_connection(ndpi_struct, flow);
  }

  if (flow->packet_counter < MSGPACK_MAX_PACKETS)
    return;

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_msgpack_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("MessagePack", ndpi_struct,
                     ndpi_search_msgpack,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_MSGPACK);
}
