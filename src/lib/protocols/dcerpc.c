/*
 * dcerpc.c
 *
 * Copyright (C) 2011-18 by ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DCERPC

#include "ndpi_api.h"
#include "ndpi_private.h"
#include <stdbool.h>

#define DCERPC_HEADER_LEN 16
#define DCERPC_MAX_REASM_LEN 65535


#define DCERPC_PKT_BIND 11

/* Interface UUIDs used for remote administration, in canonical (big endian) byte order */
static const u_int8_t dcerpc_remote_admin_uuids[][16] = {
  /* MS-SCMR (svcctl): 367abb81-9844-35f1-ad32-98f038001003 */
  { 0x36, 0x7a, 0xbb, 0x81, 0x98, 0x44, 0x35, 0xf1, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03 },
  /* MS-RRP (winreg): 338cd001-2244-31f1-aaaa-900038001003 */
  { 0x33, 0x8c, 0xd0, 0x01, 0x22, 0x44, 0x31, 0xf1, 0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03 },
  /* MS-TSCH (ITaskSchedulerService): 86d35949-83c9-4044-b424-db363231fd0c */
  { 0x86, 0xd3, 0x59, 0x49, 0x83, 0xc9, 0x40, 0x44, 0xb4, 0x24, 0xdb, 0x36, 0x32, 0x31, 0xfd, 0x0c },
  /* MS-TSCH (ATSvc): 1ff70682-0a51-30e8-076d-740be8cee98b */
  { 0x1f, 0xf7, 0x06, 0x82, 0x0a, 0x51, 0x30, 0xe8, 0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce, 0xe9, 0x8b },
  /* MS-TSCH (SASec): 378e52b0-c0a9-11cf-822d-00aa0051e40f */
  { 0x37, 0x8e, 0x52, 0xb0, 0xc0, 0xa9, 0x11, 0xcf, 0x82, 0x2d, 0x00, 0xaa, 0x00, 0x51, 0xe4, 0x0f },
};

/* Does this (connection oriented) BIND request ask for a remote administration interface? */
static bool is_remote_admin_bind(struct ndpi_packet_struct *packet)
{
  const u_int8_t *payload = packet->payload;
  u_int16_t payload_len = packet->payload_packet_len;
  u_int8_t num_ctx, i, j, uuid[16];
  u_int32_t offset;

  if(payload_len < 28 || payload[0] != 0x05 || payload[2] != DCERPC_PKT_BIND)
    return false;

  num_ctx = payload[24];
  offset = 28;
  for(i = 0; i < num_ctx; i++) {
    /* Context id (2), num transfer syntaxes (1), reserved (1), abstract syntax (16 + 4), transfer syntaxes (20 each) */
    if(offset + 24 > payload_len)
      break;

    memcpy(uuid, &payload[offset + 4], sizeof(uuid));
    if(payload[4] & 0x10) { /* Little endian: swap the first three UUID fields */
      u_int8_t t;

      t = uuid[0]; uuid[0] = uuid[3]; uuid[3] = t;
      t = uuid[1]; uuid[1] = uuid[2]; uuid[2] = t;
      t = uuid[4]; uuid[4] = uuid[5]; uuid[5] = t;
      t = uuid[6]; uuid[6] = uuid[7]; uuid[7] = t;
    }

    for(j = 0; j < sizeof(dcerpc_remote_admin_uuids) / sizeof(dcerpc_remote_admin_uuids[0]); j++) {
      if(memcmp(uuid, dcerpc_remote_admin_uuids[j], sizeof(uuid)) == 0)
        return true;
    }

    offset += 24 + 20 * payload[offset + 2];
  }

  return false;
}

static void ndpi_int_dcerpc_add_connection(struct ndpi_detection_module_struct
					     *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(packet->tcp != NULL && is_remote_admin_bind(packet)) {
    /*
      Remote administration via svcctl/winreg/task scheduler interfaces. Note that this
      traffic is generated not only by PowerShell but also by sc.exe, reg.exe,
      PsExec, Impacket and by many management/monitoring tools: we report it
      as PowerShell anyway
    */
    NDPI_LOG_INFO(ndpi_struct, "found PowerShell over DCERPC\n");
    ndpi_set_detected_protocol(ndpi_struct, &flow->core, NDPI_PROTOCOL_POWERSHELL, NDPI_PROTOCOL_DCERPC, NDPI_CONFIDENCE_DPI);
    return;
  }

  ndpi_set_detected_protocol(ndpi_struct, &flow->core, NDPI_PROTOCOL_DCERPC, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static bool is_connection_oriented_dcerpc(struct ndpi_packet_struct *packet)
{
  if((packet->tcp != NULL)
     && (packet->payload_packet_len >= 64)
     && (packet->payload[0] == 0x05) /* version 5 */
     && (packet->payload[2] < 16) /* Packet type */
		 && (((packet->payload[9]<<8) | packet->payload[8]) == packet->payload_packet_len) /* Packet Length */
     ) {
    return true;
  }
  return false;
}

static bool is_connectionless_dcerpc(struct ndpi_packet_struct *packet)
{
  u_int16_t fragment_len;
  
  if (packet->udp == NULL)
    return false;
  if (packet->payload_packet_len < 80)
    return false;
  if (packet->payload[0] != 0x04) /* type must be equal to 4 */
    return false;
  if (packet->payload[1] > 10) /* must be <= CANCEL ACK or it's not connectionless DCE/RPC */
    return false;
  if (packet->payload[3] & 0xFC) /* flags2: bit 3:8 are reserved for future use and must be set to 0 */
    return false;
  if (packet->payload[4] & 0xEE) /* neither big endian nor little endian */
    return false;
  if (packet->payload[5] > 3) /* invalid floating point type */
    return false;

  if(packet->payload[4] == 0x10)
    fragment_len = (packet->payload[75] << 8) + packet->payload[74]; /* Big endian */
  else
    fragment_len = (packet->payload[74] << 8) + packet->payload[75]; /* Little endian */

  if(packet->payload_packet_len != (fragment_len+76 /* offset */ + 4 /* rest of the packet */))
    return false; /* Too short or too long, bot RPC */
  
  return true;
}

static void dcerpc_tcp_reasm_free_dir(struct ndpi_dcerpc_tcp_reasm *reasm)
{
  if(reasm->buf != NULL)
    ndpi_free(reasm->buf);
  reasm->buf = NULL;
  reasm->cur_len = 0;
  reasm->msg_len = 0;
  reasm->next_seq = 0;
}

static int dcerpc_tcp_reasm_append(struct ndpi_dcerpc_tcp_reasm *reasm,
                                   const u_int8_t *data, u_int16_t len)
{
  u_int32_t new_len;
  u_int8_t *new_buf;

  if(len == 0)
    return 0;
  new_len = (u_int32_t)reasm->cur_len + len;
  if(new_len > DCERPC_MAX_REASM_LEN)
    return -1;
  if(reasm->buf == NULL) {
    reasm->buf = ndpi_malloc(new_len);
    if(reasm->buf == NULL)
      return -1;
    memcpy(reasm->buf, data, len);
  } else {
    new_buf = (u_int8_t *)ndpi_realloc(reasm->buf, new_len);
    if(new_buf == NULL)
      return -1;
    reasm->buf = new_buf;
    memcpy(&reasm->buf[reasm->cur_len], data, len);
  }
  reasm->cur_len = (u_int16_t)new_len;
  return 0;
}

static bool dcerpc_tcp_start_candidate(struct ndpi_packet_struct *packet)
{
  return packet->tcp != NULL && packet->payload_packet_len > 0 &&
         packet->payload[0] == 0x05;
}

static bool dcerpc_tcp_header_prefix_valid(const u_int8_t *payload, u_int16_t payload_len)
{
  if(payload_len >= 1 && payload[0] != 0x05)
    return false;
  if(payload_len >= 3 && payload[2] >= 16)
    return false;
  if(payload_len >= 4 && (payload[3] & 0xF0))
    return false;
  return true;
}

static bool dcerpc_tcp_get_fragment_len(const u_int8_t *payload, u_int16_t payload_len,
                                        u_int16_t *fragment_len)
{
  if(payload_len < 10 || !dcerpc_tcp_header_prefix_valid(payload, payload_len))
    return false;

  if(payload[4] & 0x10) /* Little endian */
    *fragment_len = ((u_int16_t)payload[9] << 8) | payload[8];
  else
    *fragment_len = ((u_int16_t)payload[8] << 8) | payload[9];

  return *fragment_len >= DCERPC_HEADER_LEN;
}

static int dcerpc_tcp_process(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  struct ndpi_dcerpc_tcp_reasm *reasm;
  const u_int8_t *original_payload = packet->payload;
  u_int16_t original_len = packet->payload_packet_len;
  u_int32_t seq = ntohl(packet->tcp->seq);
  u_int16_t fragment_len;

  if(flow->core.dcerpc_tcp_reasm == NULL) {
    if(!dcerpc_tcp_header_prefix_valid(original_payload, original_len))
      return -1;
    /* Complete messages are handled by the normal fast path above. */
    if(original_len >= 10) {
      if(!dcerpc_tcp_get_fragment_len(original_payload, original_len, &fragment_len))
        return -1;
      if(fragment_len <= original_len)
        return -1;
    }

    flow->core.dcerpc_tcp_reasm = ndpi_calloc(1, sizeof(*flow->core.dcerpc_tcp_reasm));
    if(flow->core.dcerpc_tcp_reasm == NULL)
      return -1;
  }

  reasm = &flow->core.dcerpc_tcp_reasm->dir[packet->packet_direction];
  if(reasm->cur_len == 0 && !dcerpc_tcp_header_prefix_valid(original_payload, original_len))
    goto invalid;
  if(reasm->cur_len > 0 && seq != reasm->next_seq)
    return 0;
  if(dcerpc_tcp_reasm_append(reasm, original_payload, original_len) < 0)
    goto invalid;
  reasm->next_seq = seq + original_len;

  if(reasm->cur_len < 10)
    return 0;
  if(!dcerpc_tcp_get_fragment_len(reasm->buf, reasm->cur_len, &fragment_len))
    goto invalid;
  reasm->msg_len = fragment_len;
  if(reasm->msg_len > reasm->cur_len)
    return 0;

  packet->payload = reasm->buf;
  packet->payload_packet_len = reasm->msg_len;
  if(is_connection_oriented_dcerpc(packet))
    ndpi_int_dcerpc_add_connection(ndpi_struct, flow);
  packet->payload = original_payload;
  packet->payload_packet_len = original_len;
  dcerpc_tcp_reasm_free_dir(reasm);
  return flow->core.detected_protocol_stack[0] == NDPI_PROTOCOL_DCERPC ? 1 : 0;

invalid:
  dcerpc_tcp_reasm_free_dir(reasm);
  return -1;
}

static void ndpi_search_dcerpc(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search DCERPC\n");
  if (is_connection_oriented_dcerpc(packet) || is_connectionless_dcerpc(packet)) {
    NDPI_LOG_INFO(ndpi_struct, "found DCERPC\n");
    ndpi_int_dcerpc_add_connection(ndpi_struct, flow);
    return;
  }

  if(packet->tcp != NULL && (flow->core.dcerpc_tcp_reasm != NULL ||
                             dcerpc_tcp_start_candidate(packet))) {
    if(dcerpc_tcp_process(ndpi_struct, flow) >= 0)
      return;
  }

  if(packet->payload_packet_len > 1)
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}


void init_dcerpc_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("DCERPC", ndpi_struct,
                     ndpi_search_dcerpc,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_DCERPC);
}
