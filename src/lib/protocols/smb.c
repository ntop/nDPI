/*
 * smb.c
 *
 * Copyright (C) 2016-22 - ntop.org
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
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SMBV23
#include "ndpi_api.h"
#include "ndpi_private.h"

#define SMB2_HDR_LEN             64
#define SMB2_CMD_CREATE          0x0005
#define SMB2_FLAGS_SERVER_TO_REDIR 0x00000001

static int smb_search_again(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow);

/* ************************************************************ */

static void ndpi_int_smbv23_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                           struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, &flow->core, NDPI_PROTOCOL_SMBV23, NDPI_PROTOCOL_NETBIOS, NDPI_CONFIDENCE_DPI);

  if(ndpi_struct->cfg.smb_max_packets_extra_dissection > 0) {
    NDPI_LOG_DBG(ndpi_struct, "Enabling extra dissection\n");
    /* Until we see some remote administration pipes, this is file sharing */
    flow->core.category = NDPI_PROTOCOL_CATEGORY_FILE_SHARING;
    flow->core.max_extra_packets_to_check = ndpi_struct->cfg.smb_max_packets_extra_dissection;
    flow->core.extra_packets_func = smb_search_again;
  }
}

/* ************************************************************ */

/* Is the (UTF-16LE) name of the file/pipe opened via SMB2 CREATE one of the
   names used for remote administration? */
static int is_remote_admin_name(const u_int8_t *name, u_int16_t name_len)
{
  char buf[16];
  u_int16_t i, len = 0;

  for(i = 0; i + 1 < name_len && len < sizeof(buf) - 1; i += 2) {
    if(len == 0 && name[i] == '\\' && name[i + 1] == 0)
      continue; /* Skip leading backslash */
    buf[len++] = name[i + 1] == 0 ? tolower(name[i]) : '?';
  }
  buf[len] = '\0';

  return strcmp(buf, "svcctl") == 0 ||                     /* MS-SCMR: service control manager */
         strcmp(buf, "winreg") == 0 ||                     /* MS-RRP: remote registry */
         strncmp(buf, "psexesvc", 8) == 0;                 /* PsExec binary and pipes */
}

/* ************************************************************ */

/* Look for SMB2 CREATE requests opening remote administration pipes/files.
   Return: 1 if found, -1 if we can't look into the flow anymore, 0 otherwise */
static int smb2_check_create(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;
  u_int32_t offset, msg_len, next_cmd;

  /* NetBIOS Session Service header */
  if(payload_len < 4 + 4 || payload[0] != 0x00)
    return 0;
  msg_len = (payload[1] << 16) + (payload[2] << 8) + payload[3];
  payload += 4;
  payload_len = ndpi_min(payload_len - 4, msg_len);

  if((payload[0] == 0xfd || payload[0] == 0xfc) && /* Transform (encryption) or compression header */
     payload[1] == 'S' && payload[2] == 'M' && payload[3] == 'B')
    return -1;

  offset = 0;
  while(offset + SMB2_HDR_LEN <= payload_len) {
    const u_int8_t *hdr = &payload[offset];

    if(hdr[0] != 0xfe || hdr[1] != 'S' || hdr[2] != 'M' || hdr[3] != 'B')
      break;

    next_cmd = get_l32(hdr, 20);
    if(next_cmd != 0 && (next_cmd < SMB2_HDR_LEN || next_cmd > payload_len - offset))
      break;

    if(get_l16(hdr, 12) == SMB2_CMD_CREATE &&
       (get_l32(hdr, 16) & SMB2_FLAGS_SERVER_TO_REDIR) == 0 &&
       offset + SMB2_HDR_LEN + 48 <= payload_len) {
      u_int16_t name_offset = get_l16(hdr, SMB2_HDR_LEN + 44); /* From SMB2 header */
      u_int16_t name_len = get_l16(hdr, SMB2_HDR_LEN + 46);
      u_int32_t msg_end = next_cmd ? offset + next_cmd : payload_len;

      if(name_len > 0 && name_offset >= SMB2_HDR_LEN + 48 &&
         offset + name_offset + name_len <= msg_end &&
         is_remote_admin_name(&hdr[name_offset], name_len))
        return 1;
    }

    if(next_cmd == 0)
      break;
    offset += next_cmd;
  }

  return 0;
}

/* ************************************************************ */

static int smb_search_again(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  ndpi_master_app_protocol proto;
  int rc;

  if(packet->tcp == NULL || packet->payload_packet_len == 0)
    return 1;

  rc = smb2_check_create(ndpi_struct);
  if(rc == 0)
    return 1; /* Keep looking */

  if(rc == 1) {
    /*
      Remote administration via svcctl/winreg named pipes (or PsExec).
      Note that this traffic is generated not only by PowerShell
      (i.e. Get-Service/Set-Service -ComputerName, remote registry access)
      but also by sc.exe, reg.exe, PsExec, Impacket and by many
      management/monitoring tools: we report it as PowerShell anyway
    */
    NDPI_LOG_INFO(ndpi_struct, "found PowerShell over SMBv23/NetBios\n");
    ndpi_set_detected_protocol(ndpi_struct, &flow->core, NDPI_PROTOCOL_POWERSHELL, NDPI_PROTOCOL_NETBIOS, NDPI_CONFIDENCE_DPI);
  }

  /* Remote administration or encrypted/compressed traffic (we can't tell what it is): use the default category */
  proto.master_protocol = flow->core.detected_protocol_stack[1];
  proto.app_protocol = flow->core.detected_protocol_stack[0];
  flow->core.category = get_proto_category(ndpi_struct, proto);
  return 0;
}

/* ************************************************************ */

static void ndpi_search_smb_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search SMB\n");

  /* Check connection over TCP */
  if(packet->tcp) {
    u_int16_t fourfourfive =  htons(445);
    
    if(((packet->tcp->dest == fourfourfive) || (packet->tcp->source == fourfourfive))
       && packet->payload_packet_len > (32 + 4 + 4)
       && packet->payload[0] == 0x00) {
      u_int32_t length;

      length = (packet->payload[1] << 16) + (packet->payload[2] << 8) + packet->payload[3];
      /* If the message is split into multiple TCP segments, let's hope that
         the first message we receive is the first segment */
      if(length >= (uint32_t)packet->payload_packet_len - 4) {
        u_int8_t smbv1[] = { 0xff, 0x53, 0x4d, 0x42 };
        u_int8_t smbv2[] = { 0xfe, 0x53, 0x4d, 0x42 };

        if(memcmp(&packet->payload[4], smbv1, sizeof(smbv1)) == 0) {
          if(packet->payload[8] != 0x72) /* Skip Negotiate request */ {
            NDPI_LOG_INFO(ndpi_struct, "found SMBv1\n");
            ndpi_set_detected_protocol(ndpi_struct, &flow->core, NDPI_PROTOCOL_SMBV1, NDPI_PROTOCOL_NETBIOS, NDPI_CONFIDENCE_DPI);

	    /*
	      Before we complain let's check if this is a broadacast message
	      as for broadcast we can tolerate v1 as it can be used to
	      discover old device versions.

	      As nDPI has not MAC address visibility (checking for destination MAC
	      FF:FF:FF:FF:FF:FF would have been easier) we need to implement
	      some heuristic here.
	    */

	    if(packet->payload[8] != 0x25) /* Skip SMB command Trans */
	      ndpi_set_risk(ndpi_struct, &flow->core, NDPI_SMB_INSECURE_VERSION, "Found SMBv1");
          }
          return;
        } else if(memcmp(&packet->payload[4], smbv2, sizeof(smbv2)) == 0) {
          NDPI_LOG_INFO(ndpi_struct, "found SMBv23\n");
          ndpi_int_smbv23_add_connection(ndpi_struct, flow);
          return;
        }
      }
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}


void init_smb_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("SMB", ndpi_struct,
                     ndpi_search_smb_tcp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_SMBV23);
}
