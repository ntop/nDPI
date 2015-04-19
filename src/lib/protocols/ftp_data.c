/*
 * ftp_data.c
 *
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
 * Copyright (C) 2014 - ntop.org
 * 
 * The signature is based on the Libprotoident library.
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

#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_FTP_DATA
static void ndpi_int_ftp_data_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FTP_DATA, NDPI_REAL_PROTOCOL);
}

static int ndpi_match_ftp_data_port(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->tcp->dest == htons(20) || packet->tcp->source == htons(20)) {
    return 1;
  }

  return 0;

}

static int ndpi_match_ftp_data_directory(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  if((payload_len >= 4)
      && ((packet->payload[0] == '-') || (packet->payload[0] == 'd'))
      && ((packet->payload[1] == '-') || (packet->payload[1] == 'r'))
      && ((packet->payload[2] == '-') || (packet->payload[2] == 'w'))
      && ((packet->payload[3] == '-') || (packet->payload[3] == 'x'))) {

    return 1;
  }

  return 0;

}

static int ndpi_match_file_header(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  /* A FTP packet is pretty long so 256 is a bit consrvative but it should be OK */
  if(packet->payload_packet_len < 256)
    return 0;

  /* RIFF is a meta-format for storing AVI and WAV files */
  if(match_first_bytes(packet->payload, "RIFF"))
    return 1;

  /* MZ is a .exe file */
  if((packet->payload[0] == 'M') && (packet->payload[1] == 'Z') && (packet->payload[3] == 0x00))
    return 1;

  /* Ogg files */
  if(match_first_bytes(packet->payload, "OggS"))
    return 1;

  /* ZIP files */
  if((packet->payload[0] == 'P') && (packet->payload[1] == 'K') && (packet->payload[2] == 0x03) && (packet->payload[3] == 0x04))
    return 1;

  /* MPEG files */
  if((packet->payload[0] == 0x00) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x01) && (packet->payload[3] == 0xba))
    return 1;

  /* RAR files */
  if(match_first_bytes(packet->payload, "Rar!"))
    return 1;

  /* EBML */
  if((packet->payload[0] == 0x1a) && (packet->payload[1] == 0x45) && (packet->payload[2] == 0xdf) && (packet->payload[3] == 0xa3))
    return 1;

  /* JPG */
  if((packet->payload[0] == 0xff) && (packet->payload[1] ==0xd8))
    return 1;

  /* GIF */
  if(match_first_bytes(packet->payload, "GIF8"))
    return 1;

  /* PHP scripts */
  if((packet->payload[0] == 0x3c) && (packet->payload[1] == 0x3f) && (packet->payload[2] == 0x70) && (packet->payload[3] == 0x68))
    return 1;

  /* Unix scripts */
  if((packet->payload[0] == 0x23) && (packet->payload[1] == 0x21) && (packet->payload[2] == 0x2f) && (packet->payload[3] == 0x62))
    return 1;

  /* PDFs */
  if(match_first_bytes(packet->payload, "%PDF"))
    return 1;

  /* PNG */
  if((packet->payload[0] == 0x89) && (packet->payload[1] == 'P') && (packet->payload[2] == 'N') && (packet->payload[3] == 'G'))
    return 1;

  /* HTML */
  if(match_first_bytes(packet->payload, "<htm"))
    return 1;
  if((packet->payload[0] == 0x0a) && (packet->payload[1] == '<') && (packet->payload[2] == '!') && (packet->payload[3] == 'D'))
    return 1;

  /* 7zip */
  if((packet->payload[0] == 0x37) && (packet->payload[1] == 0x7a) && (packet->payload[2] == 0xbc) && (packet->payload[3] == 0xaf))
    return 1;

  /* gzip */
  if((packet->payload[0] == 0x1f) && (packet->payload[1] == 0x8b) && (packet->payload[2] == 0x08))
    return 1;

  /* XML */
  if(match_first_bytes(packet->payload, "<!DO"))
    return 1;

  /* FLAC */
  if(match_first_bytes(packet->payload, "fLaC"))
    return 1;

  /* MP3 */
  if((packet->payload[0] == 'I') && (packet->payload[1] == 'D') && (packet->payload[2] == '3') && (packet->payload[3] == 0x03))
    return 1;
  if(match_first_bytes(packet->payload, "\xff\xfb\x90\xc0"))
    return 1;

  /* RPM */
  if((packet->payload[0] == 0xed) && (packet->payload[1] == 0xab) && (packet->payload[2] == 0xee) && (packet->payload[3] == 0xdb))
    return 1;

  /* Wz Patch */
  if(match_first_bytes(packet->payload, "WzPa"))
    return 1;

  /* Flash Video */
  if((packet->payload[0] == 'F') && (packet->payload[1] == 'L') && (packet->payload[2] == 'V') && (packet->payload[3] == 0x01))
    return 1;

  /* .BKF (Microsoft Tape Format) */
  if(match_first_bytes(packet->payload, "TAPE"))
    return 1;

  /* MS Office Doc file - this is unpleasantly geeky */
  if((packet->payload[0] == 0xd0) && (packet->payload[1] == 0xcf) && (packet->payload[2] == 0x11) && (packet->payload[3] == 0xe0))
    return 1;

  /* ASP */
  if((packet->payload[0] == 0x3c) && (packet->payload[1] == 0x25) && (packet->payload[2] == 0x40) && (packet->payload[3] == 0x20))
    return 1;

  /* WMS file */
  if((packet->payload[0] == 0x3c) && (packet->payload[1] == 0x21) && (packet->payload[2] == 0x2d) && (packet->payload[3] == 0x2d))
    return 1;

  /* ar archive, typically .deb files */
  if(match_first_bytes(packet->payload, "!<ar"))
    return 1;

  /* Raw XML (skip jabber-like traffic as this is not FTP but unencrypted jabber) */
  if((match_first_bytes(packet->payload, "<?xm"))
     && (ndpi_strnstr((const char *)packet->payload, "jabber", packet->payload_packet_len) == NULL))
    return 1;

  if(match_first_bytes(packet->payload, "<iq "))
    return 1;

  /* SPF */
  if(match_first_bytes(packet->payload, "SPFI"))
    return 1;

  /* ABIF - Applied Biosystems */
  if(match_first_bytes(packet->payload, "ABIF"))
    return 1;

  /* bzip2 - other digits are also possible instead of 9 */
  if((packet->payload[0] == 'B') && (packet->payload[1] == 'Z') && (packet->payload[2] == 'h') && (packet->payload[3] == '9'))
    return 1;

  /* Some other types of files */

  if((packet->payload[0] == '<') && (packet->payload[1] == 'c') && (packet->payload[2] == 'f'))
    return 1;
  if((packet->payload[0] == '<') && (packet->payload[1] == 'C') && (packet->payload[2] == 'F'))
    return 1;
  if(match_first_bytes(packet->payload, ".tem"))
    return 1;
  if(match_first_bytes(packet->payload, ".ite"))
    return 1;
  if(match_first_bytes(packet->payload, ".lef"))
    return 1;

  return 0;
}

static void ndpi_check_ftp_data(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  /* Check if we so far detected the protocol in the request or not. */
  if(flow->ftp_data_stage == 0) {
    NDPI_LOG(NDPI_PROTOCOL_FTP_DATA, ndpi_struct, NDPI_LOG_DEBUG, "FTP_DATA stage 0: \n");

    if((payload_len > 0) && (ndpi_match_file_header(ndpi_struct, flow) || ndpi_match_ftp_data_directory(ndpi_struct, flow) || ndpi_match_ftp_data_port(ndpi_struct, flow))) {
      NDPI_LOG(NDPI_PROTOCOL_FTP_DATA, ndpi_struct, NDPI_LOG_DEBUG, "Possible FTP_DATA request detected, we will look further for the response...\n");

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->ftp_data_stage = packet->packet_direction + 1;
    }

  } else {
    NDPI_LOG(NDPI_PROTOCOL_FTP_DATA, ndpi_struct, NDPI_LOG_DEBUG, "FTP_DATA stage %u: \n", flow->ftp_data_stage);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if((flow->ftp_data_stage - packet->packet_direction) == 1) {
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    if(payload_len == 0) {
      NDPI_LOG(NDPI_PROTOCOL_FTP_DATA, ndpi_struct, NDPI_LOG_DEBUG, "Found FTP_DATA.\n");
      ndpi_int_ftp_data_add_connection(ndpi_struct, flow);
    } else {
      NDPI_LOG(NDPI_PROTOCOL_FTP_DATA, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to FTP_DATA, resetting the stage to 0...\n");
      flow->ftp_data_stage = 0;
    }

  }
}

void ndpi_search_ftp_data(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
	
  /* Break after 20 packets. */
  if(flow->packet_counter > 20) {
    NDPI_LOG(NDPI_PROTOCOL_FTP_DATA, ndpi_struct, NDPI_LOG_DEBUG, "Exclude FTP_DATA.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FTP_DATA);
    return;
  }

  /* skip marked or retransmitted packets */
  if(packet->tcp_retransmission != 0) {
    return;
  }

  if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_FTP_DATA) {
    return;
  }

  NDPI_LOG(NDPI_PROTOCOL_FTP_DATA, ndpi_struct, NDPI_LOG_DEBUG, "FTP_DATA detection...\n");
  ndpi_check_ftp_data(ndpi_struct, flow);
}

#endif
