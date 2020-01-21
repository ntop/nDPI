/*
 * ssh.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SSH

#include "ndpi_api.h"
#include "ndpi_md5.h"

/*
  HASSH - https://github.com/salesforce/hassh

  https://github.com/salesforce/hassh/blob/master/python/hassh.py

  [server]
  skex = packet.ssh.kex_algorithms
  seastc = packet.ssh.encryption_algorithms_server_to_client
  smastc = packet.ssh.mac_algorithms_server_to_client
  scastc = packet.ssh.compression_algorithms_server_to_client
  hasshs_str = ';'.join([skex, seastc, smastc, scastc]) 

  [client]
  ckex = packet.ssh.kex_algorithms
  ceacts = packet.ssh.encryption_algorithms_client_to_server
  cmacts = packet.ssh.mac_algorithms_client_to_server
  ccacts = packet.ssh.compression_algorithms_client_to_server
  hassh_str = ';'.join([ckex, ceacts, cmacts, ccacts]) 

  NOTE
  THe ECDSA key fingerprint is SHA256 -> ssh.kex.h_sig (wireshark)
  is in the Message Code: Diffie-Hellman Key Exchange Reply (31) 
  that usually is packet 14
*/

/* #define SSH_DEBUG 1 */

static void ndpi_search_ssh_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
  
/* ************************************************************************ */

static int search_ssh_again(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_search_ssh_tcp(ndpi_struct, flow);

  if((flow->protos.ssh.hassh_client[0] != '\0')
     && (flow->protos.ssh.hassh_server[0] != '\0')) {
    /* stop extra processing */
    flow->extra_packets_func = NULL; /* We're good now */
    return(0);
  }

  /* Possibly more processing */
  return(1);
}

/* ************************************************************************ */

static void ndpi_int_ssh_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow) {
  if(flow->extra_packets_func != NULL)
    return;

  flow->guessed_host_protocol_id = flow->guessed_protocol_id = NDPI_PROTOCOL_SSH;
  
  /* This is necessary to inform the core to call this dissector again */
  flow->check_extra_packets = 1;
  flow->max_extra_packets_to_check = 12;
  flow->extra_packets_func = search_ssh_again;
  
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SSH, NDPI_PROTOCOL_UNKNOWN);
}

/* ************************************************************************ */

static u_int16_t concat_hash_string(struct ndpi_packet_struct *packet,
				   char *buf, u_int8_t client_hash) {
  u_int16_t offset = 22, buf_out_len = 0;
  u_int32_t len = ntohl(*(u_int32_t*)&packet->payload[offset]);
  offset += 4;

  /* -1 for ';' */
  if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
    goto invalid_payload;

  /* ssh.kex_algorithms [C/S] */
  strncpy(buf, (const char *)&packet->payload[offset], buf_out_len = len);
  buf[buf_out_len++] = ';';
  offset += len;

  /* ssh.server_host_key_algorithms [None] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);
  offset += 4 + len;

  /* ssh.encryption_algorithms_client_to_server [C] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  if(client_hash) {
    offset += 4;

    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
    buf[buf_out_len++] = ';';
    offset += len;
  } else
    offset += 4 + len;

  /* ssh.encryption_algorithms_server_to_client [S] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  if(!client_hash) {
    offset += 4;

    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
    buf[buf_out_len++] = ';';
    offset += len;
  } else
    offset += 4 + len;

  /* ssh.mac_algorithms_client_to_server [C] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  if(client_hash) {
    offset += 4;

    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
    buf[buf_out_len++] = ';';
    offset += len;
  } else
    offset += 4 + len;

  /* ssh.mac_algorithms_server_to_client [S] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  if(!client_hash) {
    offset += 4;

    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
    buf[buf_out_len++] = ';';
    offset += len;
  } else
    offset += 4 + len;

  /* ssh.compression_algorithms_client_to_server [C] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  if(client_hash) {
    offset += 4;

    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
    offset += len;
  } else
    offset += 4 + len;

  /* ssh.compression_algorithms_server_to_client [S] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  if(!client_hash) {
    offset += 4;

    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
    offset += len;
  } else
    offset += 4 + len;

  /* ssh.languages_client_to_server [None] */

  /* ssh.languages_server_to_client [None] */

#ifdef SSH_DEBUG
  printf("[SSH] %s\n", buf);
#endif

  return(buf_out_len);

invalid_payload:

#ifdef SSH_DEBUG
  printf("[SSH] Invalid packet payload\n");
#endif

  return(0);
}

/* ************************************************************************ */

static void ndpi_ssh_zap_cr(char *str, int len) {
  len--;

  while(len > 0) {
    if((str[len] == '\n') || (str[len] == '\r')) {
      str[len] = '\0';
      len--;
    } else
      break;
  }
}

/* ************************************************************************ */

static void ndpi_search_ssh_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

#ifdef SSH_DEBUG
  printf("[SSH] %s()\n", __FUNCTION__);
#endif

  if(flow->l4.tcp.ssh_stage == 0) {
    if(packet->payload_packet_len > 7 && packet->payload_packet_len < 100
	&& memcmp(packet->payload, "SSH-", 4) == 0) {
      int len = ndpi_min(sizeof(flow->protos.ssh.client_signature)-1, packet->payload_packet_len);
      
      strncpy(flow->protos.ssh.client_signature, (const char *)packet->payload, len);
      flow->protos.ssh.client_signature[len] = '\0';
      ndpi_ssh_zap_cr(flow->protos.ssh.client_signature, len);
      
#ifdef SSH_DEBUG
      printf("[SSH] [client_signature: %s]\n", flow->protos.ssh.client_signature);
#endif      
      
      NDPI_LOG_DBG2(ndpi_struct, "ssh stage 0 passed\n");
      flow->l4.tcp.ssh_stage = 1 + packet->packet_direction;
      ndpi_int_ssh_add_connection(ndpi_struct, flow);
      return;
    }
  } else if(flow->l4.tcp.ssh_stage == (2 - packet->packet_direction)) {
    if(packet->payload_packet_len > 7 && packet->payload_packet_len < 500
	&& memcmp(packet->payload, "SSH-", 4) == 0) {
      int len = ndpi_min(sizeof(flow->protos.ssh.server_signature)-1, packet->payload_packet_len);
      
      strncpy(flow->protos.ssh.server_signature, (const char *)packet->payload, len);
      flow->protos.ssh.server_signature[len] = '\0';
      ndpi_ssh_zap_cr(flow->protos.ssh.server_signature, len);
      
#ifdef SSH_DEBUG
      printf("[SSH] [server_signature: %s]\n", flow->protos.ssh.server_signature);
#endif
      
      NDPI_LOG_DBG2(ndpi_struct, "ssh stage 1 passed\n");
      flow->guessed_host_protocol_id = flow->guessed_protocol_id = NDPI_PROTOCOL_SSH;
      
#ifdef SSH_DEBUG
      printf("[SSH] [completed stage: %u]\n", flow->l4.tcp.ssh_stage);
#endif

      flow->l4.tcp.ssh_stage = 3;
      return;
    }
  } else if(packet->payload_packet_len > 5) {
    u_int8_t msgcode = *(packet->payload + 5);
    ndpi_MD5_CTX ctx;

    if(msgcode == 20 /* key exchange init */) {
      char *hassh_buf = calloc(packet->payload_packet_len, sizeof(char));
      u_int i, len;

#ifdef SSH_DEBUG
      printf("[SSH] [stage: %u][msg: %u][direction: %u][key exchange init]\n", flow->l4.tcp.ssh_stage, msgcode, packet->packet_direction);
#endif

      if(hassh_buf) {
	if(packet->packet_direction == 0 /* client */) {
	  u_char fingerprint_client[16];

	  len = concat_hash_string(packet, hassh_buf, 1 /* client */);

	  ndpi_MD5Init(&ctx);
	  ndpi_MD5Update(&ctx, (const unsigned char *)hassh_buf, len);
	  ndpi_MD5Final(fingerprint_client, &ctx);

#ifdef SSH_DEBUG
	  {
	    printf("[SSH] [client][%s][", hassh_buf);
	    for(i=0; i<16; i++) printf("%02X", fingerprint_client[i]);
	    printf("]\n");
	  }
#endif
	  for(i=0; i<16; i++) sprintf(&flow->protos.ssh.hassh_client[i*2], "%02X", fingerprint_client[i] & 0xFF);
	  flow->protos.ssh.hassh_client[32] = '\0';
	} else {
	  u_char fingerprint_server[16];

	  len = concat_hash_string(packet, hassh_buf, 0 /* server */);

	  ndpi_MD5Init(&ctx);
	  ndpi_MD5Update(&ctx, (const unsigned char *)hassh_buf, len);
	  ndpi_MD5Final(fingerprint_server, &ctx);

#ifdef SSH_DEBUG
	  {
	    printf("[SSH] [server][%s][", hassh_buf);
	    for(i=0; i<16; i++) printf("%02X", fingerprint_server[i]);
	    printf("]\n");
	  }
#endif

	  for(i=0; i<16; i++) sprintf(&flow->protos.ssh.hassh_server[i*2], "%02X", fingerprint_server[i] & 0xFF);
	  flow->protos.ssh.hassh_server[32] = '\0';
	}

	ndpi_free(hassh_buf);
      }

      ndpi_int_ssh_add_connection(ndpi_struct, flow);
    }

    if((flow->protos.ssh.hassh_client[0] != '\0') && (flow->protos.ssh.hassh_server[0] != '\0')) {
#ifdef SSH_DEBUG
      printf("[SSH] Dissection completed\n");
#endif
      flow->extra_packets_func = NULL; /* We're good now */
    }

    return;
  }

#ifdef SSH_DEBUG
  printf("[SSH] Excluding SSH");
#endif

  NDPI_LOG_DBG(ndpi_struct, "excluding ssh at stage %d\n", flow->l4.tcp.ssh_stage);
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SSH);
}

/* ************************************************************************ */

void init_ssh_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("SSH", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SSH,
				      ndpi_search_ssh_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
