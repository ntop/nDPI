/*
 * powershell.c
 *
 * PowerShell traffic not carried over HTTP/TLS (see http.c and tls.c for WinRM)
 *
 * Copyright (C) 2026 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_POWERSHELL

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
  Active Directory Web Services (ADWS, TCP/9389), used by the PowerShell
  ActiveDirectory module (Get-ADUser & co.), by the AD Administrative Center and
  by some AD enumeration tools (i.e. SOAPHound).
  The client starts with a .NET Message Framing [MC-NMF] preamble, sent in clear text:
  Version Record (00 01 00), Mode Record (01 xx), Via Record (02 <len> <URI>), ...
  where the URI is something like
  "net.tcp://dc.example.com:9389/ActiveDirectoryWebServices/Windows/Enumeration"
*/
static int is_adws(struct ndpi_packet_struct *packet)
{
  const u_int8_t *payload = packet->payload;
  u_int16_t payload_len = packet->payload_packet_len;
  u_int32_t via_len, offset;
  const char adws_path[] = "/ActiveDirectoryWebServices/";

  if(payload_len < 7 ||
     payload[0] != 0x00 || payload[1] != 0x01 || payload[2] != 0x00 || /* Version record: 1.0 */
     payload[3] != 0x01 || payload[4] < 0x01 || payload[4] > 0x04 ||   /* Mode record */
     payload[5] != 0x02)                                               /* Via record */
    return 0;

  /* Via length: variable-length integer (7 bits per byte); URIs longer than 16383 bytes are not interesting */
  via_len = payload[6] & 0x7F;
  offset = 7;
  if(payload[6] & 0x80) {
    if(payload_len < 8 || (payload[7] & 0x80))
      return 0;
    via_len |= payload[7] << 7;
    offset = 8;
  }

  if(via_len < 10 || offset + via_len > payload_len ||
     strncmp((const char *)&payload[offset], "net.tcp://", 10) != 0)
    return 0;

  return ndpi_strnstr((const char *)&payload[offset], adws_path, via_len) != NULL;
}

static void ndpi_search_powershell(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search PowerShell\n");

  if(is_adws(packet)) {
    /*
      Note that ADWS is not used only by PowerShell (see above):
      we report it as PowerShell anyway
    */
    NDPI_LOG_INFO(ndpi_struct, "found PowerShell (ADWS)\n");
    ndpi_set_detected_protocol(ndpi_struct, &flow->core, NDPI_PROTOCOL_POWERSHELL, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_powershell_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("PowerShell", ndpi_struct,
                          ndpi_search_powershell,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          DISSECTOR_LICENSE_LGPL,
                          1, NDPI_PROTOCOL_POWERSHELL);
}
