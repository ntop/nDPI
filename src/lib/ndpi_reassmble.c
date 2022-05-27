/*
 * ndpi_reassmble.c
 *
 * Copyright (C) 2022 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library.
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

#include "ndpi_config.h"
#include "ndpi_api.h"

/* ********************************************************************************* */

static void update_reasm_buf_bitmap(u_int8_t *buffer_bitmap,
                                    const u_int32_t buffer_bitmap_size,
                                    const u_int32_t recv_pos,
                                    const u_int32_t recv_len)
{
  if (!recv_len || !buffer_bitmap_size || recv_pos + recv_len > buffer_bitmap_size * 8)
    return;
  const u_int32_t start_byte = recv_pos / 8;
  const u_int32_t end_byte = (recv_pos + recv_len - 1) / 8;
  const u_int32_t start_bit = recv_pos % 8;
  const u_int32_t end_bit = (start_bit + recv_len - 1) % 8;
  if (start_byte == end_byte)
  {
    // fill from bit 'start_bit' until bit 'end_bit', both inclusive
    buffer_bitmap[start_byte] |= (((1U << recv_len) - 1U) << start_bit);
  } else {
    u_int32_t i;
    for (i = start_byte + 1; i <= end_byte - 1; i++)
    {
      buffer_bitmap[i] = 0xff; // completely received byte
    }
    // fill from bit 'start_bit' until bit 7, both inclusive
    buffer_bitmap[start_byte] |= ~((1U << start_bit) - 1U);
    // fill from bit 0 until bit 'end_bit', both inclusive
    buffer_bitmap[end_byte] |= (1U << (end_bit + 1U)) - 1U;
  }
}

/* ********************************************************************************* */

static uint64_t ndpi_reassemble_calculate_buffer_len(uint64_t min_len)
{
   return min_len + (8 - min_len % 8);
}

void ndpi_reassemble_set_buffer_len(struct ndpi_reasm * const reasm,
                                    uint64_t buffer_len)
{
  u_int32_t new_len = ndpi_reassemble_calculate_buffer_len(buffer_len);

  reasm->buf_req = buffer_len;

  if (reasm->buf_len == 0)
  {
    reasm->buf_len = new_len;
  } else if (new_len > reasm->buf_len) {
    uint8_t * const reasm_buf = (uint8_t *)ndpi_realloc(reasm->buf, reasm->buf_len, new_len);
    uint8_t * const reasm_buf_bitmap = (uint8_t *)ndpi_realloc(reasm->buf_bitmap, reasm->buf_len, new_len);
    if (reasm_buf != NULL && reasm_buf_bitmap != NULL) {
      reasm->buf = reasm_buf;
      reasm->buf_bitmap = reasm_buf_bitmap;

      memset(reasm->buf_bitmap + reasm->buf_len, 0, new_len - reasm->buf_len);
      reasm->buf_len = new_len;
      reasm->buf_last_pos = ndpi_min(reasm->buf_last_pos, new_len);
    }
  }
}

/* ********************************************************************************* */

int ndpi_reassemble(struct ndpi_reasm * const reasm, uint8_t const * const frag,
                    uint64_t frag_len, uint64_t frag_offset)
{
  uint64_t max_reasm_buffer_len;
  const uint64_t last_pos = frag_offset + frag_len;

  if (reasm->buf == NULL)
  {
    if (reasm->buf_len == 0)
    {
      ndpi_reassemble_set_buffer_len(reasm,
                                     4096 /* default: a couple of MTU sized packets */);
    }
    max_reasm_buffer_len = reasm->buf_len;
    reasm->buf = (uint8_t *)ndpi_malloc(max_reasm_buffer_len);
    reasm->buf_bitmap = (uint8_t *)ndpi_calloc(max_reasm_buffer_len,
                                               sizeof(uint8_t));
    if (reasm->buf == NULL || reasm->buf_bitmap == NULL)
    {
      return -1;
    }
    reasm->buf_last_pos = 0;
  } else {
    max_reasm_buffer_len = reasm->buf_len;
  }

  const uint64_t reasm_buffer_bitmap_len = reasm->buf_len / 8;

  if (last_pos > max_reasm_buffer_len)
  {
    return -3;
  }

  memcpy(&reasm->buf[frag_offset], frag, frag_len);
  if (last_pos > reasm->buf_last_pos)
  {
    reasm->buf_last_pos = last_pos;
  }
  update_reasm_buf_bitmap(reasm->buf_bitmap, reasm_buffer_bitmap_len, frag_offset, frag_len);

  return 0;
}

int ndpi_reassemble_payload(struct ndpi_reasm * const reasm, struct ndpi_packet_struct * packet)
{
  return ndpi_reassemble(reasm, packet->payload, packet->payload_packet_len, reasm->buf_last_pos);
}

/* ********************************************************************************* */

int ndpi_reassemble_in_progress(struct ndpi_reasm * const reasm)
{
  return reasm->buf_len > 0 && ndpi_reassemble_is_complete(reasm) == 0;
}

/* ********************************************************************************* */

int ndpi_reassemble_is_complete(struct ndpi_reasm * const reasm)
{
  const u_int32_t complete_bytes = reasm->buf_last_pos / 8;
  const u_int32_t remaining_bits = reasm->buf_last_pos % 8;
  u_int32_t i;

  if (reasm->buf_last_pos < reasm->buf_req)
  {
    return 0;
  }

  if (reasm->buf_last_pos > reasm->buf_req)
  {
    return 1;
  }

  for(i = 0; i < complete_bytes; i++)
  {
    if (reasm->buf_bitmap[i] != 0xff)
    {
      return 0;
    }
  }

  if (remaining_bits && reasm->buf_bitmap[complete_bytes] != (1U << (remaining_bits)) - 1)
  {
    return 0;
  }

  return 1;
}

/* ********************************************************************************* */

void ndpi_reassemble_swap_payload(struct ndpi_packet_struct * packet,
                                  struct ndpi_reasm const * reasm,
                                  u_int8_t const ** const original_payload,
                                  u_int16_t * original_payload_packet_len)
{
  if (reasm->buf == packet->payload)
  {
    packet->payload = *original_payload;
    packet->payload_packet_len = *original_payload_packet_len;
  } else {
    *original_payload = packet->payload;
    *original_payload_packet_len = packet->payload_packet_len;

    packet->payload = reasm->buf;
    packet->payload_packet_len = reasm->buf_req;
  }
}
