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
            ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SMBV1, NDPI_PROTOCOL_NETBIOS, NDPI_CONFIDENCE_DPI);

	    /*
	      Before we complain let's check if this is a broadacast message
	      as for broadcast we can tolerate v1 as it can be used to
	      discover old device versions.

	      As nDPI has not MAC address visibility (checking for destination MAC
	      FF:FF:FF:FF:FF:FF would have been easier) we need to implement
	      some heuristic here.
	    */

	    if(packet->payload[8] != 0x25) /* Skip SMB command Trans */
	      ndpi_set_risk(ndpi_struct, flow, NDPI_SMB_INSECURE_VERSION, "Found SMBv1");
          }
          return;
        } else if(memcmp(&packet->payload[4], smbv2, sizeof(smbv2)) == 0) {
          NDPI_LOG_INFO(ndpi_struct, "found SMBv23\n");
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SMBV23, NDPI_PROTOCOL_NETBIOS, NDPI_CONFIDENCE_DPI);
          return;
        }
      }
    }
  }

  NDPI_EXCLUDE_PROTO_EXT(ndpi_struct, flow, NDPI_PROTOCOL_SMBV1);
  NDPI_EXCLUDE_PROTO_EXT(ndpi_struct, flow, NDPI_PROTOCOL_SMBV23);
}


void init_smb_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("SMB", ndpi_struct, *id,
				      NDPI_PROTOCOL_SMBV23,
				      ndpi_search_smb_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
