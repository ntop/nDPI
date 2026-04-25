/*
 * ftp_data.c
 *
 * Copyright (C) 2011-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FTP_DATA

#include "ndpi_api.h"
#include "ndpi_private.h"

/* *************************************************************** */

static void ftp_data_set_detected(struct ndpi_detection_module_struct *ndpi_struct,
                                  struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_FTP_DATA, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* *************************************************************** */

/* FTP data port is TCP/20 */
static int ftp_data_on_known_port(struct ndpi_detection_module_struct *ndpi_struct) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(packet->tcp &&
     (packet->tcp->dest == htons(20) || packet->tcp->source == htons(20)))
    return 1;
  return 0;
}

/* *************************************************************** */

/*
 * Matches a Unix-style directory listing line:
 *   [d-][rwx-][rwx-][rwx-] ...
 * Each of the three permission triplets must be [rwx-] in positions 1-9.
 */
static int ftp_data_is_directory_listing(struct ndpi_detection_module_struct *ndpi_struct) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int i;

  if(packet->payload_packet_len <= 10)
    return 0;

  if(packet->payload[0] != '-' && packet->payload[0] != 'd')
    return 0;

  for(i = 0; i < 9; i += 3) {
    if(!((packet->payload[1 + i] == '-' || packet->payload[1 + i] == 'r') &&
         (packet->payload[2 + i] == '-' || packet->payload[2 + i] == 'w') &&
         (packet->payload[3 + i] == '-' || packet->payload[3 + i] == 'x')))
      return 0;
  }
  return 1;
}

/* *************************************************************** */

/*
 * Matches well-known file-format magic bytes in the first 4 bytes of payload.
 * Requires at least 256 bytes to reduce false positives.
 */
static int ftp_data_matches_file_magic(struct ndpi_detection_module_struct *ndpi_struct) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t payload_len = packet->payload_packet_len;
  const u_int8_t *p = packet->payload;

  if(payload_len < 256)
    return 0;

  /* 4-byte magic checks */
  if(ndpi_match_strprefix(p, payload_len, "RIFF")) return 1; /* AVI / WAV    */
  if(ndpi_match_strprefix(p, payload_len, "OggS")) return 1; /* Ogg          */
  if(ndpi_match_strprefix(p, payload_len, "Rar!")) return 1; /* RAR          */
  if(ndpi_match_strprefix(p, payload_len, "GIF8")) return 1; /* GIF          */
  if(ndpi_match_strprefix(p, payload_len, "%PDF")) return 1; /* PDF          */
  if(ndpi_match_strprefix(p, payload_len, "<htm")) return 1; /* HTML         */
  if(ndpi_match_strprefix(p, payload_len, "<!DO")) return 1; /* XML doctype  */
  if(ndpi_match_strprefix(p, payload_len, "fLaC")) return 1; /* FLAC         */
  if(ndpi_match_strprefix(p, payload_len, "WzPa")) return 1; /* Wz Patch     */
  if(ndpi_match_strprefix(p, payload_len, "TAPE")) return 1; /* BKF          */
  if(ndpi_match_strprefix(p, payload_len, "!<ar")) return 1; /* ar / .deb    */
  if(ndpi_match_strprefix(p, payload_len, "SPFI")) return 1; /* SPF          */
  if(ndpi_match_strprefix(p, payload_len, "ABIF")) return 1; /* Applied Bio  */
  if(ndpi_match_strprefix(p, payload_len, ".tem")) return 1;
  if(ndpi_match_strprefix(p, payload_len, ".ite")) return 1;
  if(ndpi_match_strprefix(p, payload_len, ".lef")) return 1;

  /* ZIP: PK\x03\x04 */
  if(p[0] == 'P' && p[1] == 'K' && p[2] == 0x03 && p[3] == 0x04) return 1;

  /* MPEG: \x00\x00\x01\xBA */
  if(p[0] == 0x00 && p[1] == 0x00 && p[2] == 0x01 && p[3] == 0xBA) return 1;

  /* EBML (MKV/WebM): \x1A\x45\xDF\xA3 */
  if(p[0] == 0x1A && p[1] == 0x45 && p[2] == 0xDF && p[3] == 0xA3) return 1;

  /* JPEG: \xFF\xD8 */
  if(p[0] == 0xFF && p[1] == 0xD8) return 1;

  /* PNG: \x89PNG */
  if(p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G') return 1;

  /* HTML starting with \x0A<!D */
  if(p[0] == 0x0A && p[1] == '<' && p[2] == '!' && p[3] == 'D') return 1;

  /* 7-Zip: 7z\xBC\xAF */
  if(p[0] == 0x37 && p[1] == 0x7A && p[2] == 0xBC && p[3] == 0xAF) return 1;

  /* gzip: \x1F\x8B\x08 */
  if(p[0] == 0x1F && p[1] == 0x8B && p[2] == 0x08) return 1;

  /* PHP: <?ph */
  if(p[0] == 0x3C && p[1] == 0x3F && p[2] == 0x70 && p[3] == 0x68) return 1;

  /* MP3 ID3 tag */
  if(p[0] == 'I' && p[1] == 'D' && p[2] == '3' && p[3] == 0x03) return 1;
  if(ndpi_match_strprefix(p, payload_len, "\xff\xfb\x90\xc0")) return 1;

  /* RPM: \xED\xAB\xEE\xDB */
  if(p[0] == 0xED && p[1] == 0xAB && p[2] == 0xEE && p[3] == 0xDB) return 1;

  /* Flash Video: FLV\x01 */
  if(p[0] == 'F' && p[1] == 'L' && p[2] == 'V' && p[3] == 0x01) return 1;

  /* MS Office compound document: \xD0\xCF\x11\xE0 */
  if(p[0] == 0xD0 && p[1] == 0xCF && p[2] == 0x11 && p[3] == 0xE0) return 1;

  /* ASP: <%@ */
  if(p[0] == 0x3C && p[1] == 0x25 && p[2] == 0x40 && p[3] == 0x20) return 1;

  /* WMS/HTML comment: <!-- */
  if(p[0] == 0x3C && p[1] == 0x21 && p[2] == 0x2D && p[3] == 0x2D) return 1;

  /* bzip2: BZh9 */
  if(p[0] == 'B' && p[1] == 'Z' && p[2] == 'h' && p[3] == '9') return 1;

  /* ColdFusion: <cf / <CF */
  if(p[0] == '<' && (p[1] == 'c' || p[1] == 'C') && p[2] == 'f') return 1;

  /* Raw XML (exclude Jabber) */
  if(ndpi_match_strprefix(p, payload_len, "<?xm") &&
     ndpi_strnstr((const char *)p, "jabber", payload_len) == NULL)
    return 1;
  if(ndpi_match_strprefix(p, payload_len, "<iq ")) return 1;

  return 0;
}

/* *************************************************************** */

static void ndpi_check_ftp_data(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(ndpi_seen_flow_beginning(flow) && packet->payload_packet_len > 0) {
    if(ftp_data_matches_file_magic(ndpi_struct)  ||
       ftp_data_is_directory_listing(ndpi_struct) ||
       ftp_data_on_known_port(ndpi_struct)) {
      NDPI_LOG_INFO(ndpi_struct, "found FTP_DATA request\n");
      ftp_data_set_detected(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

/* *************************************************************** */

static void ndpi_search_ftp_data(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow) {
  NDPI_LOG_DBG(ndpi_struct, "search FTP_DATA\n");
  ndpi_check_ftp_data(ndpi_struct, flow);
}

/* *************************************************************** */

void init_ftp_data_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("FTP_DATA", ndpi_struct,
                          ndpi_search_ftp_data,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_FTP_DATA);
}
