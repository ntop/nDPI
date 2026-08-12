/*
 * vnc.c
 *
 * Copyright (C) 2016-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_VNC

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * RFC 6143, Section 7.1.1 - ProtocolVersion Handshake
 *
 * Both the server and the client start the session by sending a fixed,
 * 12-byte banner of the form "RFB xxx.yyy\n", where xxx and yyy are
 * three ASCII decimal digits giving the major and minor version
 * (e.g. "RFB 003.008\n"). Either endpoint may send its banner first;
 * a VNC/RFB session is confirmed once both banners have been observed.
 */
#define VNC_RFB_BANNER_LEN 12

static int vnc_is_rfb_banner(const struct ndpi_packet_struct *packet)
{
  const u_int8_t *b = packet->payload;

  if(packet->payload_packet_len != VNC_RFB_BANNER_LEN)
    return 0;

  if(memcmp(b, "RFB ", 4) != 0 || b[7] != '.' || b[11] != 0x0a)
    return 0;

  return(ndpi_isdigit(b[4]) && ndpi_isdigit(b[5]) && ndpi_isdigit(b[6]) &&
         ndpi_isdigit(b[8]) && ndpi_isdigit(b[9]) && ndpi_isdigit(b[10]));
}

static void ndpi_search_vnc_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search vnc\n");

  if(vnc_is_rfb_banner(packet)) {
    if(flow->l4.tcp.vnc_stage == 0) {
      /* First RFB banner observed: remember which side sent it */
      NDPI_LOG_DBG2(ndpi_struct, "reached vnc stage one\n");
      flow->l4.tcp.vnc_stage = 1 + packet->packet_direction;
      return;
    }

    if(flow->l4.tcp.vnc_stage == (u_int64_t)(2 - packet->packet_direction)) {
      /* Matching RFB banner from the other side: handshake complete */
      NDPI_LOG_INFO(ndpi_struct, "found vnc\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_VNC, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      ndpi_set_risk(ndpi_struct, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found VNC"); /* Remote assistance */
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_vnc_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("VNC", ndpi_struct,
                     ndpi_search_vnc_tcp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_VNC);
}
