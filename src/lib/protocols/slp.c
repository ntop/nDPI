/*
 * slp.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SERVICE_LOCATION

#include "ndpi_api.h"
#include "ndpi_private.h"

PACK_ON
struct slp_hdr_v1 {
  uint8_t version;
  uint8_t function;
  uint16_t length;
  uint8_t flags;
  uint8_t dialect;
  uint16_t lang_code;
  uint16_t encoding;
  uint16_t xid;
} PACK_OFF;

PACK_ON
struct slp_hdr_v2 {
  uint8_t version;
  uint8_t function_id;
  PACK_ON struct {
    uint16_t high;
    uint8_t low;
  } PACK_OFF length;
  uint16_t flags;
  PACK_ON struct {
    uint16_t high;
    uint8_t low;
  } PACK_OFF next_ext_offset;
  uint16_t xid;
  uint16_t lang_tag_length;
  uint16_t lang_tag;
} PACK_OFF;

PACK_ON
struct slp_url_entry {
  uint8_t reserved;
  uint16_t lifetime;
  uint16_t length;
  // char URL[length]
  // uint8_t num_auths;
} PACK_OFF;

enum function_id {
  FID_UNKNOWN     = 0,
  FID_SrvRqst     = 1,
  FID_SrvRply     = 2,
  FID_SrvReg      = 3,
  FID_SrvDeReg    = 4,
  FID_SrvAck      = 5,
  FID_AttrRqst    = 6,
  FID_AttrRply    = 7,
  FID_DAAdvert    = 8,
  FID_SrvTypeRqst = 9,
  FID_SrvTypeRply = 10,
  FID_MAX_v1      = 11,
  FID_SAAdvert    = 11, // Not available in version 1
  FID_MAX
};

static void ndpi_int_slp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                        struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Service Location Protocol\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_SERVICE_LOCATION, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static int slp_check_packet_length(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow,
                                   unsigned int packet_length)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  if (packet->payload_packet_len != packet_length) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return 1;
  }

  return 0;
}

static int slp_check_fid(struct ndpi_detection_module_struct *ndpi_struct,
                         struct ndpi_flow_struct *flow,
                         enum function_id fid, uint8_t slp_version)
{
  if (fid <= FID_UNKNOWN) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return 1;
  }

  switch (slp_version) {
    case 0x01:
      if (fid >= FID_MAX_v1) {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return 1;
      }
      break;
    case 0x02:
      if (fid >= FID_MAX) {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return 1;
      }
      break;
    default:
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return 1;
  }

  return 0;
}

static int slp_dissect_url_entries(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow,
                                   uint16_t url_entries_offset)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  struct slp_url_entry const *url_entry;
  uint16_t url_entries_count;
  size_t i;

  if (packet->payload_packet_len <= url_entries_offset + sizeof(uint16_t)) {
    return 1;
  }
  url_entries_count = ntohs(*(uint16_t *)&packet->payload[url_entries_offset]);
  url_entries_offset += sizeof(uint16_t);

  for (i = 0; i < ndpi_min(url_entries_count, NDPI_ARRAY_LENGTH(flow->protos.slp.url)); ++i) {
    if (packet->payload_packet_len < url_entries_offset + sizeof(*url_entry)) {
      return 1;
    }
    url_entry = (struct slp_url_entry *)&packet->payload[url_entries_offset];
    url_entries_offset += sizeof(*url_entry);
    uint16_t url_length = ntohs(url_entry->length);

    if (packet->payload_packet_len < url_entries_offset + url_length + 1 /* num_auths */) {
      return 1;
    }
    url_entries_offset += url_length;

    flow->protos.slp.url_count++;
    char const * const url = (char *)&url_entry->length + sizeof(url_entry->length);
    strncpy(flow->protos.slp.url[i], url, ndpi_min(url_length, NDPI_ARRAY_LENGTH(flow->protos.slp.url[i]) - 1));
    flow->protos.slp.url[i][NDPI_ARRAY_LENGTH(flow->protos.slp.url[i]) - 1] = '\0';

    // handle Authentication Blocks
    uint8_t num_auths = packet->payload[url_entries_offset++];
    size_t j;
    for (j = 0; j < num_auths; ++j) {      
      size_t auth_block_offset = url_entries_offset + 2;
      if (packet->payload_packet_len <= auth_block_offset + 2) {
        return 1;
      }
      uint16_t auth_block_length = ntohs(*(uint16_t *)&packet->payload[auth_block_offset]);
      if (packet->payload_packet_len < auth_block_offset + auth_block_length) {
        return 1;
      }
      url_entries_offset += auth_block_length;
    }
  }

  return flow->protos.slp.url_count == 0;
}

static void ndpi_search_slp_v1(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  struct slp_hdr_v1 const * const hdr = (struct slp_hdr_v1 *)&packet->payload[0];

  NDPI_LOG_DBG(ndpi_struct, "search Service Location Protocol v1\n");

  if (packet->payload_packet_len < sizeof(*hdr)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  const unsigned int packet_length = ntohs(hdr->length);
  if (slp_check_packet_length(ndpi_struct, flow, packet_length) != 0)
    return;

  if (slp_check_fid(ndpi_struct, flow, hdr->function, hdr->version) != 0)
    return;

  ndpi_int_slp_add_connection(ndpi_struct, flow);
}

static int ndpi_search_slp_v2(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  struct slp_hdr_v2 const * const hdr = (struct slp_hdr_v2 *)&packet->payload[0];

  NDPI_LOG_DBG(ndpi_struct, "search Service Location Protocol v2\n");

  if (packet->payload_packet_len < sizeof(*hdr)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return 1;
  }

  const unsigned int packet_length = (ntohs(hdr->length.high) << 8) | hdr->length.low;
  if (slp_check_packet_length(ndpi_struct, flow, packet_length) != 0)
    return 1;

  if (slp_check_fid(ndpi_struct, flow, hdr->function_id, hdr->version) != 0)
    return 1;

  ndpi_int_slp_add_connection(ndpi_struct, flow);
  return 0;
}

static void ndpi_dissect_slp_v2(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  struct slp_hdr_v2 const * const hdr = (struct slp_hdr_v2 *)&packet->payload[0];
  int url_offset = -1; // Can be either an offset to <URL String> or <URL Entry>
  int url_length_offset = -1; // length of <URL String>
  int url_entry_count_offset = -1; // amount of <URL Entry>'s

  switch (hdr->function_id) {
    case FID_SrvRply:
      url_entry_count_offset = 2;
      url_offset = 4;
      break;
    case FID_SrvReg:
      url_offset = 3; // contains always 1 <URL Entry>
      break;
    case FID_DAAdvert:
      url_length_offset = 6;
      url_offset = 8;
      break;
    case FID_SAAdvert:
      url_length_offset = 0;
      url_offset = 2;
      break;
    case FID_AttrRqst:
      url_length_offset = 4;
      url_offset = 6;
      break;
    case FID_SrvDeReg:
      url_offset = 7; // contains always 1 <URL Entry>
      break;
  }

  if (url_offset >= 0) {
    uint16_t url_length_or_count = 0;

    if (url_length_offset > 0 && packet->payload_packet_len > sizeof(*hdr) + url_length_offset + 2) {
      // <URL String>
      url_length_or_count = ntohs(*(uint16_t *)&packet->payload[sizeof(*hdr) + url_length_offset]);
      if (packet->payload_packet_len > sizeof(*hdr) + url_offset + 2 + url_length_or_count) {
        size_t len = ndpi_min(sizeof(flow->protos.slp.url[0]) - 1, url_length_or_count);
        flow->protos.slp.url_count = 1;
        strncpy(flow->protos.slp.url[0], (char *)&packet->payload[sizeof(*hdr) + url_offset + 2], len);
        flow->protos.slp.url[0][len] = 0;
      }
    } else if (url_entry_count_offset > 0 && packet->payload_packet_len > sizeof(*hdr) + url_entry_count_offset + 2) {
      if (slp_dissect_url_entries(ndpi_struct, flow, sizeof(*hdr) + url_entry_count_offset) != 0) {
        ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid URL entries");
      }
    } else if (packet->payload_packet_len > sizeof(*hdr) + url_offset + 2) {
      url_length_or_count = ntohs(*(uint16_t *)&packet->payload[sizeof(*hdr) + url_offset]); // FID_SrvReg or FID_SrvDeReg
      if (packet->payload_packet_len > sizeof(*hdr) + url_offset + 2 + url_length_or_count) {
        size_t len = ndpi_min(sizeof(flow->protos.slp.url[0]) - 1, url_length_or_count);
        flow->protos.slp.url_count = 1;
        strncpy(flow->protos.slp.url[0], (char *)&packet->payload[sizeof(*hdr) + url_offset + 2], len);
        flow->protos.slp.url[0][len] = 0;
      }
    }
  }
}

static void ndpi_search_slp(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Service Location Protocol\n");

  switch (packet->payload[0]) {
    case 0x01:
      ndpi_search_slp_v1(ndpi_struct, flow);
      break;
    case 0x02:
      if (ndpi_search_slp_v2(ndpi_struct, flow) == 0) {
        ndpi_dissect_slp_v2(ndpi_struct, flow);
      }
      break;
    default:
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      break;
  }
}

void init_slp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                        u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Service_Location_Protocol", ndpi_struct, *id,
                                      NDPI_PROTOCOL_SERVICE_LOCATION,
                                      ndpi_search_slp,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
