/*
 * ssh.c
 *
 * Copyright (C) 2011-22 - ntop.org
 * Copyright (C) 2009-11 - ipoque GmbH
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
#include "ndpi_private.h"
#include "ndpi_md5.h"

#include <string.h>

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

// #define SSH_DEBUG 1

static void ndpi_search_ssh_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);

typedef struct {
  const char *signature;
  u_int16_t major, minor, patch;
} ssh_pattern;

/* ************************************************************************ */

static void ssh_analyze_signature_version(struct ndpi_detection_module_struct *ndpi_struct,
                                          struct ndpi_flow_struct *flow,
					  char *str_to_check,
					  u_int8_t is_client_signature) {
  u_int i;
  u_int8_t obsolete_ssh_version = 0;  
  const ssh_pattern ssh_servers_strings[] =
    {
     { (const char*)"SSH-%*f-OpenSSH_%d.%d.%d", 7, 0, 0 },     /* OpenSSH */
     { (const char*)"SSH-%*f-APACHE-SSHD-%d.%d.%d", 2, 5, 1 }, /* Apache MINA SSHD */
     { (const char*)"SSH-%*f-FileZilla_%d.%d.%d", 3, 40, 0 },  /* FileZilla SSH*/
     { (const char*)"SSH-%*f-paramiko_%d.%d.%d", 2, 4, 0 },    /* Paramiko SSH */
     { (const char*)"SSH-%*f-dropbear_%d.%d", 2020, 0, 0 },    /* Dropbear SSH */
     { NULL, 0, 0, 0 } 
    };

  for(i = 0; ssh_servers_strings[i].signature != NULL; i++) {
    int matches;
    int major   = 0;
    int minor   = 0;
    int patch   = 0;
    matches = sscanf(str_to_check, ssh_servers_strings[i].signature, &major, &minor, &patch);

    if(matches == 3 || matches == 2) {
      /* checking if is an old version */ 
      if(major < ssh_servers_strings[i].major)
	obsolete_ssh_version = 1;      
      else if(major == ssh_servers_strings[i].major) {   
	if(minor < ssh_servers_strings[i].minor)
	  obsolete_ssh_version = 1;	
	else if(minor == ssh_servers_strings[i].minor)
	  if(patch < ssh_servers_strings[i].patch)
	    obsolete_ssh_version = 1;
      }

#ifdef SSH_DEBUG
      printf("[SSH] [SSH Version: %d.%d.%d]\n", major, minor, patch);
#endif
     
      break;
    }
  }
  
  if(obsolete_ssh_version)
    ndpi_set_risk(ndpi_struct, flow,
                  (is_client_signature ? NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER : NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER),
                  NULL);
}
  
/* ************************************************************************ */

static void ssh_analyse_cipher(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow,
			       char *ciphers, u_int cipher_len,
			       u_int8_t is_client_signature) {

  char *rem;
  char *cipher;
  u_int found_obsolete_cipher = 0;
  char *cipher_copy;
  /*
    List of obsolete ciphers can be found at
    https://www.linuxminion.com/deprecated-ssh-cryptographic-settings/
  */
  const char *obsolete_ciphers[] = {
				    "arcfour256",
				    "arcfour128",
				    "3des-cbc",
				    "blowfish-cbc",
				    "cast128-cbc",
				    "arcfour",
				    NULL, 
  };

  if((cipher_copy = (char*)ndpi_malloc(cipher_len+1)) == NULL) {
#ifdef SSH_DEBUG
    printf("[SSH] Nout enough memory\n");
#endif
    return;
  }

  strncpy(cipher_copy, ciphers, cipher_len);
  cipher_copy[cipher_len] = '\0';

  cipher = strtok_r(cipher_copy, ",", &rem);

  while(cipher && !found_obsolete_cipher) {
    u_int i;
    
    for(i = 0; obsolete_ciphers[i]; i++) {
      if(strcmp(cipher, obsolete_ciphers[i]) == 0) {
        found_obsolete_cipher = i;
#ifdef SSH_DEBUG
	printf("[SSH] [SSH obsolete %s cipher][%s]\n",
	       is_client_signature ? "client" : "server",
	       obsolete_ciphers[i]);
#endif   
        break;
      }
    }

    cipher = strtok_r(NULL, ",", &rem);
  }

  if(found_obsolete_cipher) {
    char str[64];

    snprintf(str, sizeof(str), "Found cipher %s", obsolete_ciphers[found_obsolete_cipher]);
    ndpi_set_risk(ndpi_struct, flow,
		  (is_client_signature ? NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER : NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER),
		  str);
  }

  ndpi_free(cipher_copy);
}

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

  flow->max_extra_packets_to_check = 12;
  flow->extra_packets_func = search_ssh_again;
  
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SSH, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* ************************************************************************ */

static u_int16_t concat_hash_string(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow,
				    struct ndpi_packet_struct *packet,
				    char *buf, u_int8_t client_hash) {
  u_int32_t offset = 22, len, buf_out_len = 0, max_payload_len = packet->payload_packet_len-sizeof(u_int32_t);
  const u_int32_t len_max = 65565;
    
  if(offset >= max_payload_len)
    goto invalid_payload;

  len = ntohl(*(u_int32_t*)&packet->payload[offset]);
  offset += 4;

  /* -1 for ';' */
  if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
    goto invalid_payload;

  /* ssh.kex_algorithms [C/S] */
  strncpy(buf, (const char *)&packet->payload[offset], buf_out_len = len);
  buf[buf_out_len++] = ';';
  offset += len;

  if(offset >= max_payload_len)
    goto invalid_payload;
  
  /* ssh.server_host_key_algorithms [None] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  if(len > len_max)
    goto invalid_payload;
  offset += 4 + len;

  if(offset >= max_payload_len)
    goto invalid_payload;

  /* ssh.encryption_algorithms_client_to_server [C] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  offset += 4;
  if(client_hash) {
    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    ssh_analyse_cipher(ndpi_struct, flow, (char*)&packet->payload[offset], len, 1 /* client */);
    buf_out_len += len;
    buf[buf_out_len++] = ';';
  }

  if(len > len_max)
    goto invalid_payload;
  offset += len;

  if(offset >= max_payload_len)
    goto invalid_payload;

  /* ssh.encryption_algorithms_server_to_client [S] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  offset += 4;
  if(!client_hash) {
    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    ssh_analyse_cipher(ndpi_struct, flow, (char*)&packet->payload[offset], len, 0 /* server */);
    buf_out_len += len;
    buf[buf_out_len++] = ';';
  }

  if(len > len_max)
    goto invalid_payload;
  offset += len;

  if(offset >= max_payload_len)
    goto invalid_payload;
  /* ssh.mac_algorithms_client_to_server [C] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  offset += 4;
  if(client_hash) {
    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
    buf[buf_out_len++] = ';';
  }
  
  if(len > len_max)
    goto invalid_payload;
  offset += len;

  if(offset >= max_payload_len)
    goto invalid_payload;
  /* ssh.mac_algorithms_server_to_client [S] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  offset += 4;
  if(!client_hash) {
    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
    buf[buf_out_len++] = ';';
  }

  if(len > len_max)
    goto invalid_payload;
  offset += len;

  /* ssh.compression_algorithms_client_to_server [C] */
  if(offset >= max_payload_len)
    goto invalid_payload;
  
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  offset += 4;
  if(client_hash) {
    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
  }

  if(len > len_max)
    goto invalid_payload;
  offset += len;

  if(offset >= max_payload_len)
    goto invalid_payload;
  /* ssh.compression_algorithms_server_to_client [S] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  offset += 4;
  if(!client_hash) {
    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
  }

  if(len > len_max)
    goto invalid_payload;
  offset += len;

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
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

#ifdef SSH_DEBUG
  printf("[SSH] %s()\n", __FUNCTION__);
#endif

  if(flow->l4.tcp.ssh_stage == 0) {
    if(packet->payload_packet_len > 7
       && memcmp(packet->payload, "SSH-", 4) == 0) {
      int len = ndpi_min(sizeof(flow->protos.ssh.client_signature)-1, packet->payload_packet_len);
      
      strncpy(flow->protos.ssh.client_signature, (const char *)packet->payload, len);
      flow->protos.ssh.client_signature[len] = '\0';
      ndpi_ssh_zap_cr(flow->protos.ssh.client_signature, len);

      ssh_analyze_signature_version(ndpi_struct, flow, flow->protos.ssh.client_signature, 1);
      
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

      ssh_analyze_signature_version(ndpi_struct, flow, flow->protos.ssh.server_signature, 0);
      
#ifdef SSH_DEBUG
      printf("[SSH] [server_signature: %s]\n", flow->protos.ssh.server_signature);
#endif
      
      NDPI_LOG_DBG2(ndpi_struct, "ssh stage 1 passed\n");
      flow->fast_callback_protocol_id = NDPI_PROTOCOL_SSH;
      
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
      char *hassh_buf = ndpi_calloc(packet->payload_packet_len, sizeof(char));
      u_int i, len;

#ifdef SSH_DEBUG
      printf("[SSH] [stage: %u][msg: %u][direction: %u][key exchange init]\n", flow->l4.tcp.ssh_stage, msgcode, packet->packet_direction);
#endif

      if(hassh_buf) {
	if(packet->packet_direction == 0 /* client */) {
	  u_char fingerprint_client[16];

	  len = concat_hash_string(ndpi_struct, flow, packet, hassh_buf, 1 /* client */);

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
	  for(i=0; i<16; i++)
	    snprintf(&flow->protos.ssh.hassh_client[i*2],
		     sizeof(flow->protos.ssh.hassh_client) - (i*2),
		     "%02X", fingerprint_client[i] & 0xFF);
	  
	  flow->protos.ssh.hassh_client[32] = '\0';
	} else {
	  u_char fingerprint_server[16];

	  len = concat_hash_string(ndpi_struct, flow, packet, hassh_buf, 0 /* server */);

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

	  for(i=0; i<16; i++)
	    snprintf(&flow->protos.ssh.hassh_server[i*2],
		     sizeof(flow->protos.ssh.hassh_server) - (i*2),
		     "%02X", fingerprint_server[i] & 0xFF);
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

void init_ssh_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("SSH", ndpi_struct, *id,
				      NDPI_PROTOCOL_SSH,
				      ndpi_search_ssh_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
