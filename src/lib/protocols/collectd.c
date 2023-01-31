/*
 * collectd.c
 *
 * Copyright (C) 2022-23 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_COLLECTD

#include "ndpi_api.h"

#define COLLECTD_MIN_BLOCKS_REQUIRED 3
#define COLLECTD_MAX_BLOCKS_TO_DISSECT 5

#define COLLECTD_ENCR_AES256_MIN_BLOCK_SIZE 6
#define COLLECTD_ENCR_AES256_IV_SIZE 16

enum collectd_type {
  COLLECTD_TYPE_HOST            = 0x0000,
  COLLECTD_TYPE_TIME            = 0x0001,
  COLLECTD_TYPE_TIME_HR         = 0x0008,
  COLLECTD_TYPE_PLUGIN          = 0x0002,
  COLLECTD_TYPE_PLUGIN_INSTANCE = 0x0003,
  COLLECTD_TYPE_TYPE            = 0x0004,
  COLLECTD_TYPE_TYPE_INSTANCE   = 0x0005,
  COLLECTD_TYPE_VALUES          = 0x0006,
  COLLECTD_TYPE_INTERVAL        = 0x0007,
  COLLECTD_TYPE_INTERVAL_HR     = 0x0009,
  COLLECTD_TYPE_MESSAGE         = 0x0100,
  COLLECTD_TYPE_SEVERITY        = 0x0101,
  COLLECTD_TYPE_SIGN_SHA256     = 0x0200,
  COLELCTD_TYPE_ENCR_AES256     = 0x0210,
};

static u_int16_t const collectd_types[] = {
  COLLECTD_TYPE_HOST, COLLECTD_TYPE_TIME, COLLECTD_TYPE_TIME_HR, COLLECTD_TYPE_PLUGIN,
  COLLECTD_TYPE_PLUGIN_INSTANCE, COLLECTD_TYPE_TYPE, COLLECTD_TYPE_TYPE_INSTANCE,
  COLLECTD_TYPE_VALUES, COLLECTD_TYPE_INTERVAL, COLLECTD_TYPE_INTERVAL_HR,
  COLLECTD_TYPE_MESSAGE, COLLECTD_TYPE_SEVERITY, COLLECTD_TYPE_SIGN_SHA256,
  COLELCTD_TYPE_ENCR_AES256
};
static const size_t collectd_types_length = NDPI_ARRAY_LENGTH(collectd_types);

static void ndpi_int_collectd_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                             struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found collectd\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_COLLECTD,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static u_int16_t npdi_int_collectd_block_size(struct ndpi_packet_struct const * const packet,
                                              u_int16_t const block_offset)
{
  if (block_offset + 4 > packet->payload_packet_len)
  {
    return 0;
  }

  u_int16_t next_block = ntohs(get_u_int16_t(packet->payload, block_offset + 2));
  if (block_offset + next_block > packet->payload_packet_len ||
      (u_int16_t)(block_offset + next_block) <= block_offset /* possible overflow or next_block is zero */)
  {
    return 0;
  }

  return next_block;
}

static int ndpi_int_collectd_check_type(u_int16_t block_type)
{
  size_t i;

  for (i = 0; i < collectd_types_length; ++i)
  {
    if (block_type == collectd_types[i])
    {
      return 0;
    }
  }

  return 1;
}

static int ndpi_int_collectd_dissect_hostname(struct ndpi_flow_struct * const flow,
                                              struct ndpi_packet_struct const * const packet,
                                              u_int16_t block_offset, u_int16_t block_length)
{
  return (ndpi_hostname_sni_set(flow, &packet->payload[4], block_length) == NULL);
}

static int ndpi_int_collectd_dissect_username(struct ndpi_flow_struct * const flow,
                                              struct ndpi_packet_struct const * const packet,
                                              u_int16_t block_offset)
{
  u_int16_t username_length = ntohs(get_u_int16_t(packet->payload, 4));

  if(username_length > packet->payload_packet_len -
     COLLECTD_ENCR_AES256_MIN_BLOCK_SIZE -
     COLLECTD_ENCR_AES256_IV_SIZE)
  {
    return 1;
  }

  size_t sz_len = ndpi_min(sizeof(flow->protos.collectd.client_username) - 1, username_length);
  memcpy(flow->protos.collectd.client_username, &packet->payload[6], sz_len);
  flow->protos.collectd.client_username[sz_len] = '\0';

  return 0;
}

static void ndpi_search_collectd(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  u_int16_t num_blocks;
  u_int16_t block_offset = 0, block_type, block_length;
  u_int16_t hostname_offset, hostname_length = 0;

  NDPI_LOG_DBG(ndpi_struct, "search collectd\n");

  for (num_blocks = 0; num_blocks < COLLECTD_MAX_BLOCKS_TO_DISSECT;
       ++num_blocks, block_offset += block_length)
  {
    block_length = npdi_int_collectd_block_size(packet, block_offset);
    if (block_length == 0)
    {
      break;
    }

    block_type = ntohs(get_u_int16_t(packet->payload, block_offset));
    if (ndpi_int_collectd_check_type(block_type) != 0)
    {
      break;
    } else {
      if (block_type == COLLECTD_TYPE_HOST)
      {
        /*
         * Dissect the hostname later, when we are sure that it is
         * the collectd protocol.
         */
        hostname_offset = block_offset;
        hostname_length = block_length;
      } else if (block_type == COLELCTD_TYPE_ENCR_AES256) {
        /*
         * The encrypted data block is a special case.
         * It is the only dissectable block as everything else in it
         * is encrypted.
         */
        if (block_length != packet->payload_packet_len ||
            block_length < COLLECTD_ENCR_AES256_MIN_BLOCK_SIZE ||
            ndpi_int_collectd_dissect_username(flow, packet, block_offset) != 0)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        } else {
          ndpi_int_collectd_add_connection(ndpi_struct, flow);
        }
        return;
      }
    }
  }

  if (num_blocks < COLLECTD_MIN_BLOCKS_REQUIRED)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (hostname_length > 0 &&
      ndpi_int_collectd_dissect_hostname(flow, packet, hostname_offset,
                                         hostname_length) != 0)
  {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid collectd Header");
  }

  ndpi_int_collectd_add_connection(ndpi_struct, flow);
}

void init_collectd_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                             u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("collectd", ndpi_struct, *id,
    NDPI_PROTOCOL_COLLECTD,
    ndpi_search_collectd,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );

  *id += 1;
}
