/*
 * quic.c
 *
 * Copyright (C) 2012-20 - ntop.org
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 * Based on code of:
 * Andrea Buscarinu - <andrea.buscarinu@gmail.com>
 * Michele Campus - <campus@ntop.org>
 *
 */

#if defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__
#include <sys/endian.h>
#endif

#include "ndpi_protocol_ids.h"
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_QUIC
#include "ndpi_api.h"

/* This dissector handles GQUIC and IETF-QUIC both.
   Main references:
    * https://groups.google.com/a/chromium.org/g/proto-quic/c/wVHBir-uRU0?pli=1
    * https://groups.google.com/a/chromium.org/g/proto-quic/c/OAVgFqw2fko/m/jCbjP0AVAAAJ
    * https://groups.google.com/a/chromium.org/g/proto-quic/c/OAVgFqw2fko/m/-NYxlh88AgAJ
    * https://docs.google.com/document/d/1FcpCJGTDEMblAs-Bm5TYuqhHyUqeWpqrItw2vkMFsdY/edit
    * https://tools.ietf.org/html/draft-ietf-quic-tls-29
    * https://tools.ietf.org/html/draft-ietf-quic-transport-29
*/


/* Versions */
#define V_Q024		0x51303234
#define V_Q025		0x51303235
#define V_Q030		0x51303330
#define V_Q033		0x51303333
#define V_Q034		0x51303334
#define V_Q035		0x51303335
#define V_Q037		0x51303337
#define V_Q039		0x51303339
#define V_Q043		0x51303433
#define V_Q046		0x51303436
#define V_Q050		0x51303530
#define V_MVFST_22	0xfaceb001
#define V_MVFST_27	0xfaceb002

#define QUIC_MAX_CID_LENGTH  20

static int is_version_gquic(uint32_t version)
{
  return ((version & 0xFFFFFF00) == 0x51303500) /* Q05X */ ||
         ((version & 0xFFFFFF00) == 0x51303400) /* Q04X */ ||
         ((version & 0xFFFFFF00) == 0x51303300) /* Q03X */ ||
         ((version & 0xFFFFFF00) == 0x51303200) /* Q02X */;
}
static int is_version_quic(uint32_t version)
{
  return ((version & 0xFFFFFF00) == 0xFF000000) /* IETF */ ||
         ((version & 0xFFFFF000) == 0xfaceb000) /* Facebook */;
}
static int is_version_valid(uint32_t version)
{
  return is_version_gquic(version) || is_version_quic(version);
}
static uint8_t get_u8_quic_ver(uint32_t version)
{
  if((version >> 8) == 0xff0000)
    return (uint8_t)version;
  return 0;
}
static int is_quic_ver_greater_than(uint32_t version, uint8_t min_version)
{
  return get_u8_quic_ver(version) >= min_version;
}
static uint8_t get_u8_gquic_ver(uint32_t version)
{
  if(is_version_gquic(version)) {
    version = ntohl(((uint16_t)version) << 16);
    return atoi((char *)&version);
  }
  return 0;
}
static int is_gquic_ver_less_than(uint32_t version, uint8_t max_version)
{
  uint8_t u8_ver = get_u8_gquic_ver(version);
  return u8_ver && u8_ver <= max_version;
}
static int is_version_supported(uint32_t version)
{
  return (version == V_Q024 ||
          version == V_Q025 ||
          version == V_Q030 ||
          version == V_Q033 ||
          version == V_Q034 ||
          version == V_Q035 ||
          version == V_Q037 ||
          version == V_Q039 ||
          version == V_Q043 ||
          version == V_Q046 ||
          version == V_Q050 ||
	  version == V_MVFST_22 ||
	  version == V_MVFST_27 ||
          is_quic_ver_greater_than(version, 23));
}

static int quic_len(const uint8_t *buf, uint64_t *value)
{
  *value = buf[0];
  switch((*value) >> 6) {
  case 0:
    (*value) &= 0x3F;
    return 1;
  case 1:
    *value = ntohs(*(uint16_t *)buf) & 0x3FFF;
    return 2;
  case 2:
    *value = ntohl(*(uint32_t *)buf) & 0x3FFFFFFF;
    return 4;
  case 3:
    *value = ndpi_ntohll(*(uint64_t *)buf) & 0x3FFFFFFFFFFFFFFF;
    return 8;
  default: /* No Possible */
    return 0;
  }
}

static uint16_t gquic_get_u16(const uint8_t *buf, uint32_t version)
{
  if(version >= V_Q039)
    return ntohs(*(uint16_t *)buf);
  return (*(uint16_t *)buf);
}


static const uint8_t *get_crypto_data(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow,
				      uint32_t version,
				      u_int8_t *clear_payload, uint32_t clear_payload_len,
				      uint64_t *crypto_data_len)
{
  const u_int8_t *crypto_data;
  uint32_t counter;
  uint8_t first_nonzero_payload_byte, offset_len;
  uint64_t unused;

  counter = 0;
  while(clear_payload[counter] == 0 && counter < clear_payload_len)
    counter += 1;
  if(counter >= clear_payload_len)
    return NULL;
  first_nonzero_payload_byte = clear_payload[counter];
  NDPI_LOG_DBG2(ndpi_struct, "first_nonzero_payload_byte 0x%x\n", first_nonzero_payload_byte);
  if(is_gquic_ver_less_than(version, 46)) {
    if(first_nonzero_payload_byte == 0x40 ||
       first_nonzero_payload_byte == 0x60) {
      /* Probably an ACK/NACK frame: this CHLO is not the first one but try
         decoding it nonetheless */
      counter += (first_nonzero_payload_byte == 0x40) ? 6 : 9;
      if(counter >= clear_payload_len)
        return NULL;
      first_nonzero_payload_byte = clear_payload[counter];
    }
    if((first_nonzero_payload_byte != 0xA0) &&
       (first_nonzero_payload_byte != 0xA4)) {
      NDPI_LOG_DBG(ndpi_struct, "Unexpected frame 0x%x version 0x%x\n",\
		   first_nonzero_payload_byte, version);
      return NULL;
    }
    offset_len = (first_nonzero_payload_byte & 0x1C) >> 2;
    if(offset_len > 0)
      offset_len += 1;
    if(counter + 2 + offset_len + 2 /*gquic_get_u16 reads 2 bytes */  > clear_payload_len)
      return NULL;
    if(clear_payload[counter + 1] != 0x01) {
      NDPI_LOG_ERR(ndpi_struct, "Unexpected stream ID version 0x%x\n", version);
      return NULL;
    }
    counter += 2 + offset_len;
    *crypto_data_len = gquic_get_u16(&clear_payload[counter], version);
    counter += 2;
    crypto_data = &clear_payload[counter];

  } else if(version == V_Q050) {
    if(first_nonzero_payload_byte == 0x40 ||
       first_nonzero_payload_byte == 0x60) {
      /* Probably an ACK/NACK frame: this CHLO is not the first one but try
         decoding it nonetheless */
      counter += (first_nonzero_payload_byte == 0x40) ? 6 : 9;
      if(counter >= clear_payload_len)
        return NULL;
      first_nonzero_payload_byte = clear_payload[counter];
    }
    if(first_nonzero_payload_byte != 0x08) {
      NDPI_LOG_DBG(ndpi_struct, "Unexpected frame 0x%x\n", first_nonzero_payload_byte);
      return NULL;
    }
    counter += 1;
    if(counter + 8 + 8 >= clear_payload_len) /* quic_len reads 8 bytes, at most */
      return NULL;
    counter += quic_len(&clear_payload[counter], &unused);
    counter += quic_len(&clear_payload[counter], crypto_data_len);
    crypto_data = &clear_payload[counter];

  } else {  /* All other versions */
    if(first_nonzero_payload_byte != 0x06) {
      if(first_nonzero_payload_byte != 0x02 &&
         first_nonzero_payload_byte != 0x1C) {
        NDPI_LOG_ERR(ndpi_struct, "Unexpected frame 0x%x\n", first_nonzero_payload_byte);
      } else {
        NDPI_LOG_DBG(ndpi_struct, "Unexpected ACK/CC frame\n");
      }
      return NULL;
    }
    if(counter + 2 + 8 >= clear_payload_len) /* quic_len reads 8 bytes, at most */
      return NULL;
    if(clear_payload[counter + 1] != 0x00) {
      NDPI_LOG_ERR(ndpi_struct, "Unexpected crypto stream offset 0x%x\n",
		   clear_payload[counter + 1]);
      return NULL;
    }
    counter += 2;
    counter += quic_len(&clear_payload[counter], crypto_data_len);
    crypto_data = &clear_payload[counter];
  }

  if(*crypto_data_len + counter > clear_payload_len) {
    NDPI_LOG_ERR(ndpi_struct, "Invalid length %lu + %d > %d version 0x%x\n",
		 *crypto_data_len, counter, clear_payload_len, version);
    return NULL;
  }
  return crypto_data;
}

static uint8_t *get_clear_payload(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  uint32_t version, uint32_t *clear_payload_len)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t *clear_payload;
  u_int8_t dest_conn_id_len, source_conn_id_len;

  if(is_gquic_ver_less_than(version, 43)) {
    clear_payload = (uint8_t *)&packet->payload[26];
    *clear_payload_len = packet->payload_packet_len - 26;
    /* Skip Private-flag field for version for < Q34 */
    if(is_gquic_ver_less_than(version, 33)) {
      clear_payload += 1;
      (*clear_payload_len) -= 1;
    }
  } else if(version == V_Q046) {
    if(packet->payload[5] != 0x50) {
      NDPI_LOG_DBG(ndpi_struct, "Q46 invalid conn id len 0x%x\n",
		   packet->payload[5]);
      return NULL;
    }
    clear_payload = (uint8_t *)&packet->payload[30];
    *clear_payload_len = packet->payload_packet_len - 30;
  } else {
    dest_conn_id_len = packet->payload[5];
    if(dest_conn_id_len == 0 ||
       dest_conn_id_len > QUIC_MAX_CID_LENGTH) {
      NDPI_LOG_DBG(ndpi_struct, "Packet 0x%x with dest_conn_id_len %d\n",
		   version, dest_conn_id_len);
      return NULL;
    }
    source_conn_id_len = packet->payload[6 + dest_conn_id_len];
    if(source_conn_id_len > QUIC_MAX_CID_LENGTH) {
      NDPI_LOG_DBG(ndpi_struct, "Packet 0x%x with source_conn_id_len %d\n",
		   version, source_conn_id_len);
      return NULL;
    }
    /* TODO */
    clear_payload = NULL;
  }

  return clear_payload;
}

static void process_chlo(struct ndpi_detection_module_struct *ndpi_struct,
			 struct ndpi_flow_struct *flow,
			 const u_int8_t *crypto_data, uint32_t crypto_data_len)
{
  const uint8_t *tag;
  uint32_t i;
  uint16_t num_tags;
  uint32_t prev_offset;
  uint32_t tag_offset_start, offset, len, sni_len;
  ndpi_protocol_match_result ret_match;

  if(crypto_data_len < 6)
    return;
  if(memcmp(crypto_data, "CHLO", 4) != 0) {
    NDPI_LOG_ERR(ndpi_struct, "Unexpected handshake message");
    return;
  }
  num_tags = (*(uint16_t *)&crypto_data[4]);

  tag_offset_start = 8 + 8 * num_tags;
  prev_offset = 0;
  for(i = 0; i < num_tags; i++) {
    if(8 + 8 * i + 8 >= crypto_data_len)
      break;
    tag = &crypto_data[8 + 8 * i];
    offset = *((u_int32_t *)&crypto_data[8 + 8 * i + 4]);
    if(prev_offset > offset)
      break;
    len = offset - prev_offset;
    if(tag_offset_start + prev_offset + len > crypto_data_len)
      break;
#if 0
    printf("crypto_data_len %u prev_offset %u offset %u len %d\n",
		      crypto_data_len, prev_offset, offset, len);
#endif
    if((memcmp(tag, "SNI\0", 4) == 0) &&
       (tag_offset_start + prev_offset + len < crypto_data_len)) {
      sni_len = MIN(len, sizeof(flow->host_server_name) - 1);
      memcpy(flow->host_server_name,
             &crypto_data[tag_offset_start + prev_offset], sni_len);

      NDPI_LOG_DBG2(ndpi_struct, "SNI: [%s]\n", flow->host_server_name);

      ndpi_match_host_subprotocol(ndpi_struct, flow,
                                  (char *)flow->host_server_name,
                                  strlen((const char*)flow->host_server_name),
                                  &ret_match, NDPI_PROTOCOL_QUIC);
      return;
    }

    prev_offset = offset;
  }
  if(i != num_tags)
    NDPI_LOG_DBG(ndpi_struct, "Something went wrong in tags iteration\n");
}


static int may_be_initial_pkt(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow,
			      uint32_t *version)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t first_byte;
  u_int8_t pub_bit1, pub_bit2, pub_bit3, pub_bit4, pub_bit5, pub_bit7, pub_bit8;

  /* According to draft-ietf-quic-transport-29: "Clients MUST ensure that UDP
     datagrams containing Initial packets have UDP payloads of at least 1200
     bytes". Similar limit exists for previous versions */
  if(packet->payload_packet_len < 1200) {
    return 0;
  }

  first_byte = packet->payload[0];
  pub_bit1 = ((first_byte & 0x80) != 0);
  pub_bit2 = ((first_byte & 0x40) != 0);
  pub_bit3 = ((first_byte & 0x20) != 0);
  pub_bit4 = ((first_byte & 0x10) != 0);
  pub_bit5 = ((first_byte & 0x08) != 0);
  pub_bit7 = ((first_byte & 0x02) != 0);
  pub_bit8 = ((first_byte & 0x01) != 0);

  *version = 0;
  if(pub_bit1) {
    *version = ntohl(*((u_int32_t *)&packet->payload[1]));
  } else if(pub_bit5 && !pub_bit2) {
    if(!pub_bit8) {
      NDPI_LOG_DBG2(ndpi_struct, "Packet without version\n")
    } else {
      *version = ntohl(*((u_int32_t *)&packet->payload[9]));
    }
  }
  if(!is_version_valid(*version)) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid version 0x%x\n", *version);
    return 0;
  }

  if(is_gquic_ver_less_than(*version, 43) &&
     (!pub_bit5 || pub_bit3 != 0 || pub_bit4 != 0)) {
    NDPI_LOG_ERR(ndpi_struct, "Version 0x%x invalid flags 0x%x\n",
		  *version, first_byte);
    return 0;
  }
  if((*version == V_Q046) &&
     (pub_bit7 != 1 || pub_bit8 != 1)) {
    NDPI_LOG_ERR(ndpi_struct, "Q46 invalid flag 0x%x\n", first_byte);
    return 0;
  }
  if((is_version_quic(*version) || (*version == V_Q046) || (*version == V_Q050)) &&
     (pub_bit3 != 0 || pub_bit4 != 0)) {
    NDPI_LOG_DBG2(ndpi_struct, "Version 0x%x not Initial Packet\n", *version);
    return 0;
  }

  /* TODO: add some other checks to avoid false positives */

  return 1;
}

/* ***************************************************************** */

void ndpi_search_quic(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow)
{
  u_int32_t version;
  u_int8_t *clear_payload;
  uint32_t clear_payload_len;
  const u_int8_t *crypto_data;
  uint64_t crypto_data_len;
  int is_quic;

  NDPI_LOG_DBG2(ndpi_struct, "search QUIC\n");

  /* Buffers: packet->payload ---> clear_payload ---> crypto_data */

  /*
   * 1) (Very) basic heuristic to check if it is a QUIC packet.
   *    The first packet of each QUIC session should contain a valid
   *    CHLO/ClientHello message and we need (only) it to sub-classify
   *    the flow.
   *    Detecting QUIC sessions where the first captured packet is not a
   *    CHLO/CH is VERY hard. Let's try avoiding it and let's see if
   *    anyone complains...
   */

  is_quic = may_be_initial_pkt(ndpi_struct, flow, &version);
  if(!is_quic) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * 2) Ok, this packet seems to be QUIC
   */

  NDPI_LOG_INFO(ndpi_struct, "found QUIC\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_PROTOCOL_UNKNOWN);

  /*
   * 3) Skip not supported versions
   */

  if(!is_version_supported(version)) {
    NDPI_LOG_ERR(ndpi_struct, "Unsupported version 0x%x\n", version)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * 4) Extract the Payload from Initial Packets
   */
  clear_payload = get_clear_payload(ndpi_struct, flow, version, &clear_payload_len);
  if(!clear_payload) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * 5) Extract Crypto Data from the Payload
   */
  crypto_data = get_crypto_data(ndpi_struct, flow, version,
				clear_payload, clear_payload_len,
				&crypto_data_len);
  if(!crypto_data) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * 6) Process ClientHello/CHLO from the Crypto Data
   */
  if(is_version_gquic(version)) {
    process_chlo(ndpi_struct, flow, crypto_data, crypto_data_len);
  }
}

/* ***************************************************************** */

void init_quic_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("QUIC", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_QUIC, ndpi_search_quic,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
