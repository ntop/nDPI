/*
 * tftp.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TFTP

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_tftp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TFTP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static size_t tftp_dissect_szstr(struct ndpi_packet_struct const * const packet,
                                 size_t * const offset,
                                 char const ** const string_start)
{
  if (packet->payload_packet_len <= *offset)
  {
    return 0;
  }

  const union {
    uint8_t const * const as_ptr;
    char const * const as_str;
  } payload = { .as_ptr = packet->payload + *offset };

  size_t len = strnlen(payload.as_str, packet->payload_packet_len - *offset);
  if (len == 0 ||
      packet->payload_packet_len <= *offset + len ||
      payload.as_str[len] != '\0')
  {
    return 0;
  }

  if (string_start != NULL)
  {
    *string_start = payload.as_str;
  }
  *offset += len + 1;
  return len;
}

static int tftp_dissect_mode(struct ndpi_packet_struct const * const packet,
                             size_t * const offset)
{
  static char const * const valid_modes[] = {
    "netascii", "octet", "mail"
  };
  char const * string_start;
  size_t string_length = tftp_dissect_szstr(packet, offset, &string_start);
  size_t i;

  if (string_length == 0)
  {
    return 1;
  }

  for (i = 0; i < NDPI_ARRAY_LENGTH(valid_modes); ++i)
  {
    if (strncasecmp(string_start, valid_modes[i], string_length) == 0)
    {
      break;
    }
  }

  return i == NDPI_ARRAY_LENGTH(valid_modes);
}

static int tftp_dissect_options(struct ndpi_packet_struct const * const packet,
                                size_t * const offset)
{
  static char const * const valid_options[] = {
    "blksize", "tsize"
  };
  uint8_t options_used[NDPI_ARRAY_LENGTH(valid_options)] = {0, 0};
  size_t i;

  do {
    char const * string_start;
    size_t string_length = tftp_dissect_szstr(packet, offset, &string_start);

    if (string_length == 0 ||
        tftp_dissect_szstr(packet, offset, NULL) == 0 /* value, not interested */)
    {
      break;
    }

    for (i = 0; i < NDPI_ARRAY_LENGTH(valid_options); ++i)
    {
      if (strncasecmp(string_start, valid_options[i], string_length) == 0)
      {
        break;
      }
    }

    if (i == NDPI_ARRAY_LENGTH(valid_options) /* option not found in valid_options */ ||
        options_used[i] != 0 /* duplicate options are not allowed */)
    {
      break;
    }

    options_used[i] = 1;
  } while (1);

  return *offset != packet->payload_packet_len;
}

static void ndpi_search_tftp(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  u_int16_t block_num;
  u_int16_t prev_num;

  NDPI_LOG_DBG(ndpi_struct, "search TFTP\n");

  if (packet->payload_packet_len < 4 /* min. header size */ ||
      get_u_int8_t(packet->payload, 0) != 0x00)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /* parse TFTP opcode */
  switch (get_u_int8_t(packet->payload, 1))
  {
    case 0x01:
        /* Read request (RRQ) */
    case 0x02:
        /* Write request (WWQ) */

        if (packet->payload[packet->payload_packet_len - 1] != 0x00 /* last pdu element is a nul terminated string */)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }

        {
          size_t filename_len = 0;
          size_t offset = 2;
          char const * filename_start;

          filename_len = tftp_dissect_szstr(packet, &offset, &filename_start);

          /* Exclude the flow as TFPT if there was no filename and mode in the first two strings. */
          if (filename_len == 0 || ndpi_is_printable_buffer((uint8_t *)filename_start, filename_len) == 0)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }

          if (tftp_dissect_mode(packet, &offset) != 0)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }

          if (tftp_dissect_options(packet, &offset) != 0)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }

          /* Dissect RRQ/WWQ filename. */
          filename_len = ndpi_min(filename_len, sizeof(flow->protos.tftp.filename) - 1);
          memcpy(flow->protos.tftp.filename, filename_start, filename_len);
          flow->protos.tftp.filename[filename_len] = '\0';

          /* We have seen enough and do not need any more TFTP packets. */
          NDPI_LOG_INFO(ndpi_struct, "found tftp (RRQ/WWQ)\n");
          ndpi_int_tftp_add_connection(ndpi_struct, flow);
        }
        return;

    case 0x03:
        /* Data (DATA) */
        if (packet->payload_packet_len <= 4 /* min DATA header size */)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
        /* First 2 bytes were opcode so next 16 bits are the block number.
         * This should increment every packet but give some leeway for midstream and packet loss. */
        block_num = ntohs(get_u_int16_t(packet->payload, 2));
        prev_num = flow->l4.udp.tftp_data_num;
        flow->l4.udp.tftp_data_num = block_num;
        if (!(block_num == prev_num + 1 || (prev_num != 0 && block_num == prev_num)))
        {
          return;
        }
        break;

    case 0x04:
        /* Acknowledgment (ACK) */

        if (packet->payload_packet_len != 4 /* ACK has a fixed packet size */)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
        /* First 2 bytes were opcode so next 16 bits are the block number.
         * This should increment every packet but give some leeway for midstream and packet loss. */
        block_num = ntohs(get_u_int16_t(packet->payload, 2));
        prev_num = flow->l4.udp.tftp_ack_num;
        flow->l4.udp.tftp_ack_num = block_num;
        if (!(block_num == prev_num + 1 || (block_num == prev_num)))
        {
          return;
        }
        break;

    case 0x05:
        /* Error (ERROR) */

        if (packet->payload_packet_len < 5 ||
            packet->payload[packet->payload_packet_len - 1] != 0x00 ||
            packet->payload[2] != 0x00 || packet->payload[3] > 0x07)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
        break;

    case 0x06:
        /* Option Acknowledgment (OACK) */

        {
          size_t offset = 2;

          if (tftp_dissect_options(packet, &offset) != 0)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }
        }

        /* We have seen enough and do not need any more TFTP packets. */
        NDPI_LOG_INFO(ndpi_struct, "found tftp (OACK)\n");
        ndpi_int_tftp_add_connection(ndpi_struct, flow);
        break;

    default:
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
  }

  if (flow->l4.udp.tftp_stage < 3)
  {
    NDPI_LOG_DBG2(ndpi_struct, "maybe tftp. need next packet\n");
    flow->l4.udp.tftp_stage++;
    return;
  }

  NDPI_LOG_INFO(ndpi_struct, "found tftp\n");
  ndpi_int_tftp_add_connection(ndpi_struct, flow);
}


void init_tftp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("TFTP", ndpi_struct, *id,
				      NDPI_PROTOCOL_TFTP,
				      ndpi_search_tftp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

