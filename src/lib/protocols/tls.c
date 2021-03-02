/*
 * tls.c - SSL/TLS/DTLS dissector
 *
 * Copyright (C) 2016-21 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TLS

#include "ndpi_api.h"
#include "ndpi_md5.h"
#include "ndpi_sha1.h"

extern char *strptime(const char *s, const char *format, struct tm *tm);
extern int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow, uint32_t quic_version);
extern int http_process_user_agent(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow,
                                   const u_int8_t *ua_ptr, u_int16_t ua_ptr_len);
/* QUIC/GQUIC stuff */
extern int quic_len(const uint8_t *buf, uint64_t *value);
extern int quic_len_buffer_still_required(uint8_t value);
extern int is_version_with_var_int_transport_params(uint32_t version);

// #define DEBUG_TLS_MEMORY       1
// #define DEBUG_TLS              1
// #define DEBUG_TLS_BLOCKS          1
// #define DEBUG_CERTIFICATE_HASH

/* #define DEBUG_FINGERPRINT      1 */
/* #define DEBUG_ENCRYPTED_SNI    1 */

/*
  NOTE

  How to view the certificate fingerprint
  1. Using wireshark save the certificate on certificate.bin file as explained
     in https://security.stackexchange.com/questions/123851/how-can-i-extract-the-certificate-from-this-pcap-file

  2. openssl x509 -inform der -in certificate.bin -text > certificate.der
  3. openssl x509 -noout -fingerprint -sha1 -inform pem -in certificate.der
     SHA1 Fingerprint=15:9A:76....

  $ shasum -a 1 www.grc.com.bin
    159a76.....
 */

#define NDPI_MAX_TLS_REQUEST_SIZE 10000

/* skype.c */
extern u_int8_t is_skype_flow(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow);

/* stun.c */
extern u_int32_t get_stun_lru_key(struct ndpi_flow_struct *flow, u_int8_t rev);

static void ndpi_int_tls_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow, u_int32_t protocol);

/* **************************************** */

static u_int32_t ndpi_tls_refine_master_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						 struct ndpi_flow_struct *flow, u_int32_t protocol) {
  struct ndpi_packet_struct *packet = &flow->packet;

  // protocol = NDPI_PROTOCOL_TLS;

  if(packet->tcp != NULL) {
    switch(protocol) {
    case NDPI_PROTOCOL_TLS:
      {
	/*
	  In case of SSL there are probably sub-protocols
	  such as IMAPS that can be otherwise detected
	*/
	u_int16_t sport = ntohs(packet->tcp->source);
	u_int16_t dport = ntohs(packet->tcp->dest);

	if((sport == 465) || (dport == 465) || (sport == 587) || (dport == 587))
	  protocol = NDPI_PROTOCOL_MAIL_SMTPS;
	else if((sport == 993) || (dport == 993)
		|| (flow->l4.tcp.mail_imap_starttls)
		) protocol = NDPI_PROTOCOL_MAIL_IMAPS;
	else if((sport == 995) || (dport == 995)) protocol = NDPI_PROTOCOL_MAIL_POPS;
      }
      break;
    }
  }

  return(protocol);
}

/* **************************************** */

void ndpi_search_tls_tcp_memory(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int avail_bytes;

  /* TCP */
#ifdef DEBUG_TLS_MEMORY
  printf("[TLS Mem] Handling TCP/TLS flow [payload_len: %u][buffer_len: %u][direction: %u]\n",
	 packet->payload_packet_len,
	 flow->l4.tcp.tls.message.buffer_len,
	 packet->packet_direction);
#endif

  if(flow->l4.tcp.tls.message.buffer == NULL) {
    /* Allocate buffer */
    flow->l4.tcp.tls.message.buffer_len = 2048, flow->l4.tcp.tls.message.buffer_used = 0;
    flow->l4.tcp.tls.message.buffer = (u_int8_t*)ndpi_malloc(flow->l4.tcp.tls.message.buffer_len);

    if(flow->l4.tcp.tls.message.buffer == NULL)
      return;

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Allocating %u buffer\n", flow->l4.tcp.tls.message.buffer_len);
#endif
  }

  avail_bytes = flow->l4.tcp.tls.message.buffer_len - flow->l4.tcp.tls.message.buffer_used;

  if(avail_bytes < packet->payload_packet_len) {
    u_int new_len = flow->l4.tcp.tls.message.buffer_len + packet->payload_packet_len - avail_bytes + 1;
    void *newbuf  = ndpi_realloc(flow->l4.tcp.tls.message.buffer,
				 flow->l4.tcp.tls.message.buffer_len, new_len);
    if(!newbuf) return;

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Enlarging %u -> %u buffer\n", flow->l4.tcp.tls.message.buffer_len, new_len);
#endif

    flow->l4.tcp.tls.message.buffer = (u_int8_t*)newbuf;
    flow->l4.tcp.tls.message.buffer_len = new_len;
    avail_bytes = flow->l4.tcp.tls.message.buffer_len - flow->l4.tcp.tls.message.buffer_used;
  }

  if(packet->payload_packet_len > 0 && avail_bytes >= packet->payload_packet_len) {
    u_int8_t ok = 0;

    if(flow->l4.tcp.tls.message.next_seq[packet->packet_direction] != 0) {
      if(ntohl(packet->tcp->seq) == flow->l4.tcp.tls.message.next_seq[packet->packet_direction])
	ok = 1;
    } else
      ok = 1;

    if(ok) {
      memcpy(&flow->l4.tcp.tls.message.buffer[flow->l4.tcp.tls.message.buffer_used],
	     packet->payload, packet->payload_packet_len);

      flow->l4.tcp.tls.message.buffer_used += packet->payload_packet_len;
#ifdef DEBUG_TLS_MEMORY
      printf("[TLS Mem] Copied data to buffer [%u/%u bytes][direction: %u][tcp_seq: %u][next: %u]\n",
	     flow->l4.tcp.tls.message.buffer_used, flow->l4.tcp.tls.message.buffer_len,
	     packet->packet_direction,
	     ntohl(packet->tcp->seq),
	     ntohl(packet->tcp->seq)+packet->payload_packet_len);
#endif

      flow->l4.tcp.tls.message.next_seq[packet->packet_direction] = ntohl(packet->tcp->seq)+packet->payload_packet_len;
    } else {
#ifdef DEBUG_TLS_MEMORY
      printf("[TLS Mem] Skipping packet [%u bytes][direction: %u][tcp_seq: %u][expected next: %u]\n",
	     flow->l4.tcp.tls.message.buffer_len,
	     packet->packet_direction,
	     ntohl(packet->tcp->seq),
	     ntohl(packet->tcp->seq)+packet->payload_packet_len);
#endif
    }
  }
}

/* **************************************** */

/* Can't call libc functions from kernel space, define some stub instead */

#define ndpi_isalpha(ch) (((ch) >= 'a' && (ch) <= 'z') || ((ch) >= 'A' && (ch) <= 'Z'))
#define ndpi_isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#define ndpi_isspace(ch) (((ch) >= '\t' && (ch) <= '\r') || ((ch) == ' '))
#define ndpi_isprint(ch) ((ch) >= 0x20 && (ch) <= 0x7e)
#define ndpi_ispunct(ch) (((ch) >= '!' && (ch) <= '/') ||	\
			  ((ch) >= ':' && (ch) <= '@') ||	\
			  ((ch) >= '[' && (ch) <= '`') ||	\
			  ((ch) >= '{' && (ch) <= '~'))

/* **************************************** */

static void cleanupServerName(char *buffer, int buffer_len) {
  u_int i;

  /* Now all lowecase */
  for(i=0; i<buffer_len; i++)
    buffer[i] = tolower(buffer[i]);
}

/* **************************************** */

/*
  Return code
  -1: error (buffer too short)
   0: OK but buffer is not human readeable (so something went wrong)
   1: OK
 */
static int extractRDNSequence(struct ndpi_packet_struct *packet,
			      u_int offset, char *buffer, u_int buffer_len,
			      char *rdnSeqBuf, u_int *rdnSeqBuf_offset,
			      u_int rdnSeqBuf_len,
			      const char *label) {
  u_int8_t str_len = packet->payload[offset+4], is_printable = 1;
  char *str;
  u_int len, j;

  if (*rdnSeqBuf_offset >= rdnSeqBuf_len) {
#ifdef DEBUG_TLS
    printf("[TLS] %s() [buffer capacity reached][%u]\n",
           __FUNCTION__, rdnSeqBuf_len);
#endif
    return -1;
  }

  // packet is truncated... further inspection is not needed
  if((offset+4+str_len) >= packet->payload_packet_len)
    return(-1);

  str = (char*)&packet->payload[offset+5];

  len = (u_int)ndpi_min(str_len, buffer_len-1);
  strncpy(buffer, str, len);
  buffer[len] = '\0';

  // check string is printable
  for(j = 0; j < len; j++) {
    if(!ndpi_isprint(buffer[j])) {
      is_printable = 0;
      break;
    }
  }

  if(is_printable) {
    int rc = snprintf(&rdnSeqBuf[*rdnSeqBuf_offset],
		      rdnSeqBuf_len-(*rdnSeqBuf_offset),
		      "%s%s=%s", (*rdnSeqBuf_offset > 0) ? ", " : "",
		      label, buffer);

    if(rc > 0)
      (*rdnSeqBuf_offset) += rc;
  }

  return(is_printable);
}

/* **************************************** */

/* See https://blog.catchpoint.com/2017/05/12/dissecting-tls-using-wireshark/ */
static void processCertificateElements(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow,
				       u_int16_t p_offset, u_int16_t certificate_len) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int num_found = 0, i;
  char buffer[64] = { '\0' }, rdnSeqBuf[2048] = { '\0' };
  u_int rdn_len = 0;

#ifdef DEBUG_TLS
  printf("[TLS] %s() [offset: %u][certificate_len: %u]\n", __FUNCTION__, p_offset, certificate_len);
#endif

  /* Check after handshake protocol header (5 bytes) and message header (4 bytes) */
  for(i = p_offset; i < certificate_len; i++) {
    /*
       See https://www.ibm.com/support/knowledgecenter/SSFKSJ_7.5.0/com.ibm.mq.sec.doc/q009860_.htm
       for X.509 certificate labels
    */
    if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x03)) {
      /* Common Name */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "CN");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Common Name", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x06)) {
      /* Country */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "C");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Country", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x07)) {
      /* Locality */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "L");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Locality", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x08)) {
      /* State or Province */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "ST");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "State or Province", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x0a)) {
      /* Organization Name */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "O");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Organization Name", buffer);
#endif

    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x0b)) {
      /* Organization Unit */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "OU");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Organization Unit", buffer);
#endif
    } else if((packet->payload[i] == 0x30) && (packet->payload[i+1] == 0x1e) && (packet->payload[i+2] == 0x17)) {
      /* Certificate Validity */
      u_int8_t len = packet->payload[i+3];
      u_int offset = i+4;

      if(num_found == 0) {
	num_found++;

#ifdef DEBUG_TLS
	printf("[TLS] %s() IssuerDN [%s]\n", __FUNCTION__, rdnSeqBuf);
#endif

	if(rdn_len && (flow->protos.tls_quic_stun.tls_quic.issuerDN == NULL))
	  flow->protos.tls_quic_stun.tls_quic.issuerDN = ndpi_strdup(rdnSeqBuf);

	rdn_len = 0; /* Reset buffer */
      }

      if((offset+len) < packet->payload_packet_len) {
	char utcDate[32];

#ifdef DEBUG_TLS
	u_int j;

	printf("[CERTIFICATE] notBefore [len: %u][", len);
	for(j=0; j<len; j++) printf("%c", packet->payload[i+4+j]);
	printf("]\n");
#endif

	if(len < (sizeof(utcDate)-1)) {
	  struct tm utc;
	  utc.tm_isdst = -1; /* Not set by strptime */

	  strncpy(utcDate, (const char*)&packet->payload[i+4], len);
	  utcDate[len] = '\0';

	  /* 141021000000Z */
	  if(strptime(utcDate, "%y%m%d%H%M%SZ", &utc) != NULL) {
	    flow->protos.tls_quic_stun.tls_quic.notBefore = timegm(&utc);
#ifdef DEBUG_TLS
	    printf("[CERTIFICATE] notBefore %u [%s]\n",
		   flow->protos.tls_quic_stun.tls_quic.notBefore, utcDate);
#endif
	  }
	}

	offset += len;

	if((offset+1) < packet->payload_packet_len) {
	  len = packet->payload[offset+1];

	  offset += 2;

	  if((offset+len) < packet->payload_packet_len) {
	    u_int32_t time_sec = flow->packet.current_time_ms / 1000;
#ifdef DEBUG_TLS
	    u_int j;

	    printf("[CERTIFICATE] notAfter [len: %u][", len);
	    for(j=0; j<len; j++) printf("%c", packet->payload[offset+j]);
	    printf("]\n");
#endif

	    if(len < (sizeof(utcDate)-1)) {
	      struct tm utc;
	      utc.tm_isdst = -1; /* Not set by strptime */

	      strncpy(utcDate, (const char*)&packet->payload[offset], len);
	      utcDate[len] = '\0';

	      /* 141021000000Z */
	      if(strptime(utcDate, "%y%m%d%H%M%SZ", &utc) != NULL) {
		flow->protos.tls_quic_stun.tls_quic.notAfter = timegm(&utc);
#ifdef DEBUG_TLS
		printf("[CERTIFICATE] notAfter %u [%s]\n",
		       flow->protos.tls_quic_stun.tls_quic.notAfter, utcDate);
#endif
	      }
	    }


	    if((time_sec < flow->protos.tls_quic_stun.tls_quic.notBefore)
	       || (time_sec > flow->protos.tls_quic_stun.tls_quic.notAfter))
	    ndpi_set_risk(flow, NDPI_TLS_CERTIFICATE_EXPIRED); /* Certificate expired */
	  }
	}
      }
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x1d) && (packet->payload[i+2] == 0x11)) {
      /* Organization OID: 2.5.29.17 (subjectAltName) */
      u_int8_t matched_name = 0;

#ifdef DEBUG_TLS
      printf("******* [TLS] Found subjectAltName\n");
#endif

      i += 3 /* skip the initial patten 55 1D 11 */;
      i++; /* skip the first type, 0x04 == BIT STRING, and jump to it's length */
      if(i < packet->payload_packet_len) {
	i += (packet->payload[i] & 0x80) ? (packet->payload[i] & 0x7F) : 0; /* skip BIT STRING length */
	if(i < packet->payload_packet_len) {
	  i += 2; /* skip the second type, 0x30 == SEQUENCE, and jump to it's length */
	  if(i < packet->payload_packet_len) {
	    i += (packet->payload[i] & 0x80) ? (packet->payload[i] & 0x7F) : 0; /* skip SEQUENCE length */
	    i++;

	    while(i < packet->payload_packet_len) {
	      if(packet->payload[i] == 0x82) {
		if((i < (packet->payload_packet_len - 1))
		   && ((i + packet->payload[i + 1] + 2) < packet->payload_packet_len)) {
		  u_int8_t len = packet->payload[i + 1];
		  char dNSName[256];

		  i += 2;

		  /* The check "len > sizeof(dNSName) - 1" will be always false. If we add it,
		     the compiler is smart enough to detect it and throws a warning */
		  if((len == 0 /* Looks something went wrong */)
		     || ((i+len) >  packet->payload_packet_len))
		    break;

		  strncpy(dNSName, (const char*)&packet->payload[i], len);
		  dNSName[len] = '\0';

		  cleanupServerName(dNSName, len);

#if DEBUG_TLS
		  printf("[TLS] dNSName %s [%s][len: %u][leftover: %d]\n", dNSName,
			 flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, len,
			 packet->payload_packet_len-i-len);
#endif
		  if(matched_name == 0) {
		    if(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name[0] == '\0')
		      matched_name = 1;	/* No SNI */
		    else if((dNSName[0] == '*') && strstr(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, &dNSName[1]))
		      matched_name = 1;
		    else if(strcmp(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, dNSName) == 0)
		      matched_name = 1;
		  }

		  if(flow->protos.tls_quic_stun.tls_quic.server_names == NULL)
		    flow->protos.tls_quic_stun.tls_quic.server_names = ndpi_strdup(dNSName),
		      flow->protos.tls_quic_stun.tls_quic.server_names_len = strlen(dNSName);
		  else {
		    u_int16_t dNSName_len = strlen(dNSName);
		    u_int16_t newstr_len = flow->protos.tls_quic_stun.tls_quic.server_names_len + dNSName_len + 1;
		    char *newstr = (char*)ndpi_realloc(flow->protos.tls_quic_stun.tls_quic.server_names,
						       flow->protos.tls_quic_stun.tls_quic.server_names_len+1, newstr_len+1);

		    if(newstr) {
		      flow->protos.tls_quic_stun.tls_quic.server_names = newstr;
		      flow->protos.tls_quic_stun.tls_quic.server_names[flow->protos.tls_quic_stun.tls_quic.server_names_len] = ',';
		      strncpy(&flow->protos.tls_quic_stun.tls_quic.server_names[flow->protos.tls_quic_stun.tls_quic.server_names_len+1],
			      dNSName, dNSName_len+1);
		      flow->protos.tls_quic_stun.tls_quic.server_names[newstr_len] = '\0';
		      flow->protos.tls_quic_stun.tls_quic.server_names_len = newstr_len;
		    }
		  }

		  if(!flow->l4.tcp.tls.subprotocol_detected)
		    if(ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TLS, dNSName, len))
		      flow->l4.tcp.tls.subprotocol_detected = 1;

		  i += len;
		} else {
#if DEBUG_TLS
		  printf("[TLS] Leftover %u bytes", packet->payload_packet_len - i);
#endif
		  break;
		}
	      } else {
		break;
	      }
	    } /* while */

	    if(!matched_name)
	      ndpi_set_risk(flow, NDPI_TLS_CERTIFICATE_MISMATCH); /* Certificate mismatch */
	  }
	}
      }
    }
  }

  if(rdn_len && (flow->protos.tls_quic_stun.tls_quic.subjectDN == NULL)) {
    flow->protos.tls_quic_stun.tls_quic.subjectDN = ndpi_strdup(rdnSeqBuf);

    if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
      /* No idea what is happening behind the scenes: let's check the certificate */
      u_int32_t proto_id;
      int rc = ndpi_match_string_value(ndpi_struct->tls_cert_subject_automa.ac_automa,
				       rdnSeqBuf, strlen(rdnSeqBuf),&proto_id);

      if(rc == 0)
	flow->detected_protocol_stack[0] = proto_id,
	  flow->detected_protocol_stack[1] = NDPI_PROTOCOL_TLS;
    }
  }

  if(flow->protos.tls_quic_stun.tls_quic.subjectDN && flow->protos.tls_quic_stun.tls_quic.issuerDN
     && (!strcmp(flow->protos.tls_quic_stun.tls_quic.subjectDN, flow->protos.tls_quic_stun.tls_quic.issuerDN)))
    ndpi_set_risk(flow, NDPI_TLS_SELFSIGNED_CERTIFICATE);

#if DEBUG_TLS
  printf("[TLS] %s() SubjectDN [%s]\n", __FUNCTION__, rdnSeqBuf);
#endif
}

/* **************************************** */

/* See https://blog.catchpoint.com/2017/05/12/dissecting-tls-using-wireshark/ */
int processCertificate(struct ndpi_detection_module_struct *ndpi_struct,
		       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  int is_dtls = packet->udp ? 1 : 0;
  u_int32_t certificates_length, length = (packet->payload[1] << 16) + (packet->payload[2] << 8) + packet->payload[3];
  u_int32_t certificates_offset = 7 + (is_dtls ? 8 : 0);
  u_int8_t num_certificates_found = 0;
  SHA1_CTX srv_cert_fingerprint_ctx ;

#ifdef DEBUG_TLS
  printf("[TLS] %s() [payload_packet_len=%u][direction: %u][%02X %02X %02X %02X %02X %02X...]\n",
	 __FUNCTION__, packet->payload_packet_len,
	 packet->packet_direction,
	 packet->payload[0], packet->payload[1], packet->payload[2],
	 packet->payload[3], packet->payload[4], packet->payload[5]);
#endif

  if((packet->payload_packet_len != (length + 4 + (is_dtls ? 8 : 0))) || (packet->payload[1] != 0x0)) {
    ndpi_set_risk(flow, NDPI_MALFORMED_PACKET);
    return(-1); /* Invalid length */
  }

  certificates_length = (packet->payload[certificates_offset - 3] << 16) +
                        (packet->payload[certificates_offset - 2] << 8) +
                        packet->payload[certificates_offset - 1];

  if((packet->payload[certificates_offset - 3] != 0x0) || ((certificates_length+3) != length)) {
    ndpi_set_risk(flow, NDPI_MALFORMED_PACKET);
    return(-2); /* Invalid length */
  }

  /* Now let's process each individual certificates */
  while(certificates_offset < certificates_length) {
    u_int32_t certificate_len = (packet->payload[certificates_offset] << 16) + (packet->payload[certificates_offset+1] << 8) + packet->payload[certificates_offset+2];

    /* Invalid lenght */
    if((certificate_len == 0)
       || (packet->payload[certificates_offset] != 0x0)
       || ((certificates_offset+certificate_len) > (4+certificates_length+(is_dtls ? 8 : 0)))) {
#ifdef DEBUG_TLS
      printf("[TLS] Invalid length [certificate_len: %u][certificates_offset: %u][%u vs %u]\n",
	     certificate_len, certificates_offset,
	     (certificates_offset+certificate_len),
	     certificates_length);
#endif
      break;
    }

    certificates_offset += 3;
#ifdef DEBUG_TLS
    printf("[TLS] Processing %u bytes certificate [%02X %02X %02X]\n",
	   certificate_len,
	   packet->payload[certificates_offset],
	   packet->payload[certificates_offset+1],
	   packet->payload[certificates_offset+2]);
#endif

    if(num_certificates_found++ == 0) /* Dissect only the first certificate that is the one we care */ {
      /* For SHA-1 we take into account only the first certificate and not all of them */

      SHA1Init(&srv_cert_fingerprint_ctx);

#ifdef DEBUG_CERTIFICATE_HASH
      {
	int i;

	for(i=0;i<certificate_len;i++)
	  printf("%02X ", packet->payload[certificates_offset+i]);

	printf("\n");
      }
#endif

      SHA1Update(&srv_cert_fingerprint_ctx,
		 &packet->payload[certificates_offset],
		 certificate_len);

      SHA1Final(flow->protos.tls_quic_stun.tls_quic.sha1_certificate_fingerprint, &srv_cert_fingerprint_ctx);

      flow->l4.tcp.tls.fingerprint_set = 1;

      uint8_t * sha1 = flow->protos.tls_quic_stun.tls_quic.sha1_certificate_fingerprint;
      const size_t sha1_siz = sizeof(flow->protos.tls_quic_stun.tls_quic.sha1_certificate_fingerprint);
      char sha1_str[sha1_siz * 2 + 1];
      static const char hexalnum[] = "0123456789ABCDEF";
      for (size_t i = 0; i < sha1_siz; ++i) {
        u_int8_t lower = (sha1[i] & 0x0F);
        u_int8_t upper = (sha1[i] & 0xF0) >> 4;
        sha1_str[i*2] = hexalnum[upper];
        sha1_str[i*2 + 1] = hexalnum[lower];
      }
      sha1_str[sha1_siz * 2] = '\0';

#ifdef DEBUG_TLS
      printf("[TLS] SHA-1: %s\n", sha1_str);
#endif

      if (ndpi_struct->malicious_sha1_automa.ac_automa != NULL) {
        u_int16_t rc1 = ndpi_match_string(ndpi_struct->malicious_sha1_automa.ac_automa, sha1_str);

        if(rc1 > 0)
          ndpi_set_risk(flow, NDPI_MALICIOUS_SHA1);
      }

      processCertificateElements(ndpi_struct, flow, certificates_offset, certificate_len);
    }

    certificates_offset += certificate_len;
  }

  if((ndpi_struct->num_tls_blocks_to_follow != 0)
     && (flow->l4.tcp.tls.num_tls_blocks >= ndpi_struct->num_tls_blocks_to_follow)) {
#ifdef DEBUG_TLS_BLOCKS
    printf("*** [TLS Block] Enough blocks dissected\n");
#endif

    flow->extra_packets_func = NULL; /* We're good now */
  }

  return(1);
}

/* **************************************** */

static int processTLSBlock(struct ndpi_detection_module_struct *ndpi_struct,
			   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  int ret;

  switch(packet->payload[0] /* block type */) {
  case 0x01: /* Client Hello */
  case 0x02: /* Server Hello */
    processClientServerHello(ndpi_struct, flow, 0);
    flow->l4.tcp.tls.hello_processed = 1;
    ndpi_int_tls_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TLS);

#ifdef DEBUG_TLS
    printf("*** TLS [version: %02X][%s Hello]\n",
	   flow->protos.tls_quic_stun.tls_quic.ssl_version,
	   (packet->payload[0] == 0x01) ? "Client" : "Server");
#endif

    if((flow->protos.tls_quic_stun.tls_quic.ssl_version >= 0x0304 /* TLS 1.3 */)
       && (packet->payload[0] == 0x02 /* Server Hello */)) {
      flow->l4.tcp.tls.certificate_processed = 1; /* No Certificate with TLS 1.3+ */
    }
    break;

  case 0x0b: /* Certificate */
    /* Important: populate the tls union fields only after
     * ndpi_int_tls_add_connection has been called */
    if(flow->l4.tcp.tls.hello_processed) {
      ret = processCertificate(ndpi_struct, flow);
      if (ret != 1) {
#ifdef DEBUG_TLS
        printf("[TLS] Error processing certificate: %d\n", ret);
#endif
      }
      flow->l4.tcp.tls.certificate_processed = 1;
    }
    break;

  default:
    return(-1);
  }

  return(0);
}

/* **************************************** */

static void ndpi_looks_like_tls(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  // ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TLS, NDPI_PROTOCOL_UNKNOWN);

  if(flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN)
    flow->guessed_protocol_id = NDPI_PROTOCOL_TLS;
}

/* **************************************** */

static int ndpi_search_tls_tcp(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t something_went_wrong = 0;

#ifdef DEBUG_TLS_MEMORY
  printf("[TLS Mem] ndpi_search_tls_tcp() Processing new packet [payload_packet_len: %u]\n",
	 packet->payload_packet_len);
#endif

  if(packet->payload_packet_len == 0)
    return(1); /* Keep working */

  ndpi_search_tls_tcp_memory(ndpi_struct, flow);

  while(!something_went_wrong) {
    u_int16_t len, p_len;
    const u_int8_t *p;
    u_int8_t content_type;

    if(flow->l4.tcp.tls.message.buffer_used < 5)
      return(1); /* Keep working */

    len = (flow->l4.tcp.tls.message.buffer[3] << 8) + flow->l4.tcp.tls.message.buffer[4] + 5;

    if(len > flow->l4.tcp.tls.message.buffer_used) {
#ifdef DEBUG_TLS_MEMORY
      printf("[TLS Mem] Not enough TLS data [%u < %u][%02X %02X %02X %02X %02X]\n",
	     len, flow->l4.tcp.tls.message.buffer_used,
	     flow->l4.tcp.tls.message.buffer[0],
	     flow->l4.tcp.tls.message.buffer[1],
	     flow->l4.tcp.tls.message.buffer[2],
	     flow->l4.tcp.tls.message.buffer[3],
	     flow->l4.tcp.tls.message.buffer[4]);
#endif
      break;
    }

    if(len == 0) {
      something_went_wrong = 1;
      break;
    }

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Processing %u bytes message\n", len);
#endif

    content_type = flow->l4.tcp.tls.message.buffer[0];

    /* Overwriting packet payload */
    p = packet->payload;
    p_len = packet->payload_packet_len; /* Backup */

    if(content_type == 0x14 /* Change Cipher Spec */) {
      if(ndpi_struct->skip_tls_blocks_until_change_cipher) {
	/*
	  Ignore Application Data up until change cipher
	  so in this case we reset the number of observed
	  TLS blocks
	*/
	flow->l4.tcp.tls.num_tls_blocks = 0;
      }
    }

    if((len > 9)
       && (content_type != 0x17 /* Application Data */)
       && (!flow->l4.tcp.tls.certificate_processed)) {
      /* Split the element in blocks */
      u_int16_t processed = 5;

      while((processed+4) <= len) {
	const u_int8_t *block = (const u_int8_t *)&flow->l4.tcp.tls.message.buffer[processed];
	u_int32_t block_len   = (block[1] << 16) + (block[2] << 8) + block[3];

	if(/* (block_len == 0) || */ /* Note blocks can have zero lenght */
	   (block_len > len) || ((block[1] != 0x0))) {
	  something_went_wrong = 1;
	  break;
	}

	packet->payload = block;
	packet->payload_packet_len = ndpi_min(block_len+4, flow->l4.tcp.tls.message.buffer_used);

	if((processed+packet->payload_packet_len) > len) {
	  something_went_wrong = 1;
	  break;
	}

	processTLSBlock(ndpi_struct, flow);
	ndpi_looks_like_tls(ndpi_struct, flow);

	processed += packet->payload_packet_len;
      }
    } else {
      /* Process element as a whole */
      if(content_type == 0x17 /* Application Data */) {
	ndpi_looks_like_tls(ndpi_struct, flow);

	if(flow->l4.tcp.tls.certificate_processed) {
	  if(flow->l4.tcp.tls.num_tls_blocks < ndpi_struct->num_tls_blocks_to_follow)
	    flow->l4.tcp.tls.tls_application_blocks_len[flow->l4.tcp.tls.num_tls_blocks++] =
	      (packet->packet_direction == 0) ? (len-5) : -(len-5);

#ifdef DEBUG_TLS_BLOCKS
	  printf("*** [TLS Block] [len: %u][num_tls_blocks: %u/%u]\n",
		 len-5, flow->l4.tcp.tls.num_tls_blocks, ndpi_struct->num_tls_blocks_to_follow);
#endif
	}
      }
    }

    packet->payload = p;
    packet->payload_packet_len = p_len; /* Restore */
    flow->l4.tcp.tls.message.buffer_used -= len;

    if(flow->l4.tcp.tls.message.buffer_used > 0)
      memmove(flow->l4.tcp.tls.message.buffer,
	      &flow->l4.tcp.tls.message.buffer[len],
	      flow->l4.tcp.tls.message.buffer_used);
    else
      break;

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Left memory buffer %u bytes\n", flow->l4.tcp.tls.message.buffer_used);
#endif
  }

  if(something_went_wrong
     || ((ndpi_struct->num_tls_blocks_to_follow > 0)
	 && (flow->l4.tcp.tls.num_tls_blocks == ndpi_struct->num_tls_blocks_to_follow))
     ) {
#ifdef DEBUG_TLS_BLOCKS
    printf("*** [TLS Block] No more blocks\n");
#endif
    flow->check_extra_packets = 0;
    flow->extra_packets_func = NULL;
    return(0); /* That's all */
  } else
    return(1);
}

/* **************************************** */

static int ndpi_search_tls_udp(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t handshake_len;
  u_int16_t p_len, processed;
  const u_int8_t *p;
  u_int8_t no_dtls = 0, change_cipher_found = 0;

#ifdef DEBUG_TLS
  printf("[TLS] %s()\n", __FUNCTION__);
#endif

  /* Overwriting packet payload */
  p = packet->payload, p_len = packet->payload_packet_len; /* Backup */

  /* Split the element in blocks */
  processed = 0;
  while(processed + 13 < p_len) {
    u_int32_t block_len;
    const u_int8_t *block = (const u_int8_t *)&p[processed];

    if((block[0] != 0x16 && block[0] != 0x14) || /* Handshake, change-cipher-spec */
       (block[1] != 0xfe) || /* We ignore old DTLS versions */
       ((block[2] != 0xff) && (block[2] != 0xfd))) {
#ifdef DEBUG_TLS
      printf("[TLS] DTLS invalid block 0x%x or old version 0x%x-0x%x-0x%x\n",
             block[0], block[1], block[2], block[3]);
#endif
      no_dtls = 1;
      break;
    }
    block_len = ntohs(*((u_int16_t*)&block[11]));
#ifdef DEBUG_TLS
    printf("[TLS] DTLS block len: %d\n", block_len);
#endif
    if (block_len == 0 || (processed + block_len + 12 >= p_len)) {
#ifdef DEBUG_TLS
      printf("[TLS] DTLS invalid block len %d (processed %d, p_len %d)\n",
             block_len, processed, p_len);
#endif
      no_dtls = 1;
      break;
    }
    /* We process only handshake msgs */
    if(block[0] == 0x16) {
      if (processed + block_len + 13 > p_len) {
#ifdef DEBUG_TLS
        printf("[TLS] DTLS invalid len %d %d %d\n", processed, block_len, p_len);
#endif
        no_dtls = 1;
        break;
     }
      /* TODO: handle (certificate) fragments */
      handshake_len = (block[14] << 16) + (block[15] << 8) + block[16];
      if((handshake_len + 12) != block_len) {
#ifdef DEBUG_TLS
        printf("[TLS] DTLS invalid handshake_len %d, %d)\n",
               handshake_len, block_len);
#endif
        no_dtls = 1;
        break;
      }
      packet->payload = &block[13];
      packet->payload_packet_len = block_len;
      processTLSBlock(ndpi_struct, flow);
    } else {
      /* Change-cipher-spec: any subsequent block might be encrypted */
#ifdef DEBUG_TLS
      printf("[TLS] Change-cipher-spec\n");
#endif
      change_cipher_found = 1;
      processed += block_len + 13;
      break;
    }

    processed += block_len + 13;
  }
  if(processed != p_len) {
#ifdef DEBUG_TLS
    printf("[TLS] DTLS invalid processed len %d/%d (%d)\n", processed, p_len, change_cipher_found);
#endif
    if(!change_cipher_found)
      no_dtls = 1;
  }

  packet->payload = p;
  packet->payload_packet_len = p_len; /* Restore */

  if(no_dtls || change_cipher_found) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return(0); /* That's all */
  } else {
    return(1); /* Keep working */
  }
}

/* **************************************** */

static void tlsInitExtraPacketProcessing(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow) {
  flow->check_extra_packets = 1;

  /* At most 12 packets should almost always be enough to find the server certificate if it's there */
  flow->max_extra_packets_to_check = 12 + (ndpi_struct->num_tls_blocks_to_follow*4);
  flow->extra_packets_func = (flow->packet.udp != NULL) ? ndpi_search_tls_udp : ndpi_search_tls_tcp;
}

/* **************************************** */

static void ndpi_int_tls_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow, u_int32_t protocol) {
#if DEBUG_TLS
  printf("[TLS] %s()\n", __FUNCTION__);
#endif

  if((flow->packet.udp != NULL) && (protocol == NDPI_PROTOCOL_TLS))
    protocol = NDPI_PROTOCOL_DTLS;

  if((flow->detected_protocol_stack[0] == protocol)
     || (flow->detected_protocol_stack[1] == protocol)) {
    if(!flow->check_extra_packets)
      tlsInitExtraPacketProcessing(ndpi_struct, flow);
    return;
  }

  if(protocol != NDPI_PROTOCOL_TLS)
    ;
  else
    protocol = ndpi_tls_refine_master_protocol(ndpi_struct, flow, protocol);

  ndpi_set_detected_protocol(ndpi_struct, flow, protocol, protocol);

  tlsInitExtraPacketProcessing(ndpi_struct, flow);
}

/* **************************************** */

/* https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967 */

#define JA3_STR_LEN 1024
#define MAX_NUM_JA3  512

struct ja3_info {
  u_int16_t tls_handshake_version;
  u_int16_t num_cipher, cipher[MAX_NUM_JA3];
  u_int16_t num_tls_extension, tls_extension[MAX_NUM_JA3];
  u_int16_t num_elliptic_curve, elliptic_curve[MAX_NUM_JA3];
  u_int16_t num_elliptic_curve_point_format, elliptic_curve_point_format[MAX_NUM_JA3];
};

/* **************************************** */

int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow, uint32_t quic_version) {
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ja3_info ja3;
  u_int8_t invalid_ja3 = 0;
  u_int16_t tls_version, ja3_str_len;
  char ja3_str[JA3_STR_LEN];
  ndpi_MD5_CTX ctx;
  u_char md5_hash[16];
  int i;
  u_int16_t total_len;
  u_int8_t handshake_type;
  char buffer[64] = { '\0' };
  int is_quic = (quic_version != 0);
  int is_dtls = packet->udp && (!is_quic);

#ifdef DEBUG_TLS
  printf("SSL %s() called\n", __FUNCTION__);
#endif

  memset(&ja3, 0, sizeof(ja3));

  handshake_type = packet->payload[0];
  total_len = (packet->payload[1] << 16) +  (packet->payload[2] << 8) + packet->payload[3];

  if((total_len > packet->payload_packet_len) || (packet->payload[1] != 0x0))
    return(0); /* Not found */

  total_len = packet->payload_packet_len;

  /* At least "magic" 3 bytes, null for string end, otherwise no need to waste cpu cycles */
  if(total_len > 4) {
    u_int16_t base_offset    = (!is_dtls) ? 38 : 46;
    u_int16_t version_offset = (!is_dtls) ? 4 : 12;
    u_int16_t offset = (!is_dtls) ? 38 : 46, extension_len, j;
    u_int8_t  session_id_len =  0;
    if (base_offset < total_len)
      session_id_len = packet->payload[base_offset];

#ifdef DEBUG_TLS
    printf("SSL [len: %u][handshake_type: %02X]\n", packet->payload_packet_len, handshake_type);
#endif

    tls_version = ntohs(*((u_int16_t*)&packet->payload[version_offset]));
    flow->protos.tls_quic_stun.tls_quic.ssl_version = ja3.tls_handshake_version = tls_version;
    if(flow->protos.tls_quic_stun.tls_quic.ssl_version < 0x0302) /* TLSv1.1 */
      ndpi_set_risk(flow, NDPI_TLS_OBSOLETE_VERSION);

    if(handshake_type == 0x02 /* Server Hello */) {
      int i, rc;

#ifdef DEBUG_TLS
      printf("SSL Server Hello [version: 0x%04X]\n", tls_version);
#endif

      /*
	The server hello decides about the SSL version of this flow
	https://networkengineering.stackexchange.com/questions/55752/why-does-wireshark-show-version-tls-1-2-here-instead-of-tls-1-3
      */
      if(packet->udp)
	offset += session_id_len + 1;
      else {
	if(tls_version < 0x7F15 /* TLS 1.3 lacks of session id */)
	  offset += session_id_len+1;
      }

      if((offset+3) > packet->payload_packet_len)
	return(0); /* Not found */

      ja3.num_cipher = 1, ja3.cipher[0] = ntohs(*((u_int16_t*)&packet->payload[offset]));
      if((flow->protos.tls_quic_stun.tls_quic.server_unsafe_cipher = ndpi_is_safe_ssl_cipher(ja3.cipher[0])) == 1)
	ndpi_set_risk(flow, NDPI_TLS_WEAK_CIPHER);

      flow->protos.tls_quic_stun.tls_quic.server_cipher = ja3.cipher[0];

#ifdef DEBUG_TLS
      printf("TLS [server][session_id_len: %u][cipher: %04X]\n", session_id_len, ja3.cipher[0]);
#endif

      offset += 2 + 1;

      if((offset + 1) < packet->payload_packet_len) /* +1 because we are goint to read 2 bytes */
	extension_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
      else
	extension_len = 0;

#ifdef DEBUG_TLS
      printf("TLS [server][extension_len: %u]\n", extension_len);
#endif
      offset += 2;

      for(i=0; i<extension_len; ) {
	u_int16_t extension_id, extension_len;

	if((offset+4) > packet->payload_packet_len) break;

	extension_id  = ntohs(*((u_int16_t*)&packet->payload[offset]));
	extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+2]));

	if(ja3.num_tls_extension < MAX_NUM_JA3)
	  ja3.tls_extension[ja3.num_tls_extension++] = extension_id;

#ifdef DEBUG_TLS
	printf("TLS [server][extension_id: %u/0x%04X][len: %u]\n",
	       extension_id, extension_id, extension_len);
#endif

	if(extension_id == 43 /* supported versions */) {
	  if(extension_len >= 2) {
	    u_int16_t tls_version = ntohs(*((u_int16_t*)&packet->payload[offset+4]));

#ifdef DEBUG_TLS
	    printf("TLS [server] [TLS version: 0x%04X]\n", tls_version);
#endif

	    flow->protos.tls_quic_stun.tls_quic.ssl_version = tls_version;
	  }
	}

	i += 4 + extension_len, offset += 4 + extension_len;
      }

      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.tls_handshake_version);

      for(i=0; i<ja3.num_cipher; i++) {
	rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.cipher[i]);

	if(rc <= 0) break; else ja3_str_len += rc;
      }

      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
      if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc;

      /* ********** */

      for(i=0; i<ja3.num_tls_extension; i++) {
	int rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.tls_extension[i]);

	if(rc <= 0) break; else ja3_str_len += rc;
      }

#ifdef DEBUG_TLS
      printf("TLS [server] %s\n", ja3_str);
#endif

#ifdef DEBUG_TLS
      printf("[JA3] Server: %s \n", ja3_str);
#endif

      ndpi_MD5Init(&ctx);
      ndpi_MD5Update(&ctx, (const unsigned char *)ja3_str, strlen(ja3_str));
      ndpi_MD5Final(md5_hash, &ctx);

      for(i=0, j=0; i<16; i++) {
	int rc = snprintf(&flow->protos.tls_quic_stun.tls_quic.ja3_server[j],
			  sizeof(flow->protos.tls_quic_stun.tls_quic.ja3_server)-j, "%02x", md5_hash[i]);
	if(rc <= 0) break; else j += rc;
      }

#ifdef DEBUG_TLS
      printf("[JA3] Server: %s \n", flow->protos.tls_quic_stun.tls_quic.ja3_server);
#endif
    } else if(handshake_type == 0x01 /* Client Hello */) {
      u_int16_t cipher_len, cipher_offset;
      u_int8_t cookie_len = 0;

      if((session_id_len+base_offset+3) > packet->payload_packet_len)
	return(0); /* Not found */

      if(!is_dtls) {
	cipher_len = packet->payload[session_id_len+base_offset+2] + (packet->payload[session_id_len+base_offset+1] << 8);
	cipher_offset = base_offset + session_id_len + 3;
      } else {
	cookie_len = packet->payload[base_offset+session_id_len+1];
#ifdef DEBUG_TLS
	printf("[JA3] Client: DTLS cookie len %d\n", cookie_len);
#endif
	if((session_id_len+base_offset+cookie_len+4) > packet->payload_packet_len)
	  return(0); /* Not found */
	cipher_len = ntohs(*((u_int16_t*)&packet->payload[base_offset+session_id_len+cookie_len+2]));
	cipher_offset = base_offset + session_id_len + cookie_len + 4;
      }

#ifdef DEBUG_TLS
      printf("Client SSL [client cipher_len: %u][tls_version: 0x%04X]\n", cipher_len, tls_version);
#endif

      if((cipher_offset+cipher_len) <= total_len) {
	for(i=0; i<cipher_len;) {
	  u_int16_t *id = (u_int16_t*)&packet->payload[cipher_offset+i];

#ifdef DEBUG_TLS
	  printf("Client SSL [cipher suite: %u/0x%04X] [%d/%u]\n", ntohs(*id), ntohs(*id), i, cipher_len);
#endif
	  if((*id == 0) || (packet->payload[cipher_offset+i] != packet->payload[cipher_offset+i+1])) {
	    /*
	      Skip GREASE [https://tools.ietf.org/id/draft-ietf-tls-grease-01.html]
	      https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967
	    */

	    if(ja3.num_cipher < MAX_NUM_JA3)
	      ja3.cipher[ja3.num_cipher++] = ntohs(*id);
	    else {
	      invalid_ja3 = 1;
#ifdef DEBUG_TLS
	      printf("Client SSL Invalid cipher %u\n", ja3.num_cipher);
#endif
	    }
	  }

	  i += 2;
	}
      } else {
	invalid_ja3 = 1;
#ifdef DEBUG_TLS
	printf("Client SSL Invalid len %u vs %u\n", (cipher_offset+cipher_len), total_len);
#endif
      }

      offset = base_offset + session_id_len + cookie_len + cipher_len + 2;

      if(offset < total_len) {
	u_int16_t compression_len;
	u_int16_t extensions_len;

	offset += (!is_dtls) ? 1 : 2;
	compression_len = packet->payload[offset];
	offset++;

#ifdef DEBUG_TLS
	printf("Client SSL [compression_len: %u]\n", compression_len);
#endif

	// offset += compression_len + 3;
	offset += compression_len;

	if(offset < total_len) {
	  extensions_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
	  offset += 2;

#ifdef DEBUG_TLS
	  printf("Client SSL [extensions_len: %u]\n", extensions_len);
#endif

	  if((extensions_len+offset) <= total_len) {
	    /* Move to the first extension
	       Type is u_int to avoid possible overflow on extension_len addition */
	    u_int extension_offset = 0;
	    u_int32_t j;

	    while(extension_offset < extensions_len) {
	      u_int16_t extension_id, extension_len, extn_off = offset+extension_offset;

	      extension_id = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
	      extension_offset += 2;

	      extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
	      extension_offset += 2;

#ifdef DEBUG_TLS
	      printf("Client SSL [extension_id: %u][extension_len: %u]\n", extension_id, extension_len);
#endif

	      if((extension_id == 0) || (packet->payload[extn_off] != packet->payload[extn_off+1])) {
		/* Skip GREASE */

		if(ja3.num_tls_extension < MAX_NUM_JA3)
		  ja3.tls_extension[ja3.num_tls_extension++] = extension_id;
		else {
		  invalid_ja3 = 1;
#ifdef DEBUG_TLS
		  printf("Client SSL Invalid extensions %u\n", ja3.num_tls_extension);
#endif
		}
	      }

	      if(extension_id == 0 /* server name */) {
		u_int16_t len;

#ifdef DEBUG_TLS
		printf("[TLS] Extensions: found server name\n");
#endif

		len = (packet->payload[offset+extension_offset+3] << 8) + packet->payload[offset+extension_offset+4];
		len = (u_int)ndpi_min(len, sizeof(buffer)-1);

		if((offset+extension_offset+5+len) <= packet->payload_packet_len) {
		  strncpy(buffer, (char*)&packet->payload[offset+extension_offset+5], len);
		  buffer[len] = '\0';

		  cleanupServerName(buffer, sizeof(buffer));

		  snprintf(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name,
			   sizeof(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name),
			   "%s", buffer);
#ifdef DEBUG_TLS
		  printf("[TLS] SNI: [%s]\n", buffer);
#endif
		  if(!is_quic) {
		    if(ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TLS, buffer, strlen(buffer)))
		      flow->l4.tcp.tls.subprotocol_detected = 1;
		  } else {
		    if(ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, buffer, strlen(buffer)))
		      flow->l4.tcp.tls.subprotocol_detected = 1;
		  }
	  
		  if(ndpi_check_dga_name(ndpi_struct, flow,
					 flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, 1)) {
		    char *sni = flow->protos.tls_quic_stun.tls_quic.client_requested_server_name;
		    int len = strlen(sni);

#ifdef DEBUG_TLS
		    printf("[TLS] SNI: (DGA) [%s]\n", flow->protos.tls_quic_stun.tls_quic.client_requested_server_name);
#endif
		    
		    if((len >= 4)
		       && strcmp(&sni[len-4], ".com") /* Check if it ends in .com or .net */
		       && strcmp(&sni[len-4], ".net")
		       && strncmp(sni, "www.", 4)) /* Not starting with www.... */
		      ;
		    else
		      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TOR, NDPI_PROTOCOL_TLS);
		  } else {
#ifdef DEBUG_TLS
		    printf("[TLS] SNI: (NO DGA) [%s]\n", flow->protos.tls_quic_stun.tls_quic.client_requested_server_name);
#endif
		  }
		} else {
#ifdef DEBUG_TLS
		  printf("[TLS] Extensions server len too short: %u vs %u\n",
			 offset+extension_offset+5+len,
			 packet->payload_packet_len);
#endif
		}
	      } else if(extension_id == 10 /* supported groups */) {
		u_int16_t s_offset = offset+extension_offset + 2;

#ifdef DEBUG_TLS
		printf("Client SSL [EllipticCurveGroups: len=%u]\n", extension_len);
#endif

		if((s_offset+extension_len-2) <= total_len) {
		  for(i=0; i<extension_len-2;) {
		    u_int16_t s_group = ntohs(*((u_int16_t*)&packet->payload[s_offset+i]));

#ifdef DEBUG_TLS
		    printf("Client SSL [EllipticCurve: %u/0x%04X]\n", s_group, s_group);
#endif
		    if((s_group == 0) || (packet->payload[s_offset+i] != packet->payload[s_offset+i+1])) {
		      /* Skip GREASE */
		      if(ja3.num_elliptic_curve < MAX_NUM_JA3)
			ja3.elliptic_curve[ja3.num_elliptic_curve++] = s_group;
		      else {
			invalid_ja3 = 1;
#ifdef DEBUG_TLS
			printf("Client SSL Invalid num elliptic %u\n", ja3.num_elliptic_curve);
#endif
		      }
		    }

		    i += 2;
		  }
		} else {
		  invalid_ja3 = 1;
#ifdef DEBUG_TLS
		  printf("Client SSL Invalid len %u vs %u\n", (s_offset+extension_len-1), total_len);
#endif
		}
	      } else if(extension_id == 11 /* ec_point_formats groups */) {
		u_int16_t s_offset = offset+extension_offset + 1;

#ifdef DEBUG_TLS
		printf("Client SSL [EllipticCurveFormat: len=%u]\n", extension_len);
#endif
		if((s_offset+extension_len-1) <= total_len) {
		  for(i=0; i<extension_len-1;i++) {
		    u_int8_t s_group = packet->payload[s_offset+i];

#ifdef DEBUG_TLS
		    printf("Client SSL [EllipticCurveFormat: %u]\n", s_group);
#endif

		    if(ja3.num_elliptic_curve_point_format < MAX_NUM_JA3)
		      ja3.elliptic_curve_point_format[ja3.num_elliptic_curve_point_format++] = s_group;
		    else {
		      invalid_ja3 = 1;
#ifdef DEBUG_TLS
		      printf("Client SSL Invalid num elliptic %u\n", ja3.num_elliptic_curve_point_format);
#endif
		    }
		  }
		} else {
		  invalid_ja3 = 1;
#ifdef DEBUG_TLS
		  printf("Client SSL Invalid len %u vs %u\n", s_offset+extension_len, total_len);
#endif
		}
	      } else if(extension_id == 16 /* application_layer_protocol_negotiation */) {
		u_int16_t s_offset = offset+extension_offset;
		u_int16_t tot_alpn_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		char alpn_str[256];
		u_int8_t alpn_str_len = 0;

#ifdef DEBUG_TLS
		printf("Client SSL [ALPN: block_len=%u/len=%u]\n", extension_len, tot_alpn_len);
#endif
		s_offset += 2;
		tot_alpn_len += s_offset;

		while(s_offset < tot_alpn_len && s_offset < total_len) {
		  u_int8_t alpn_i, alpn_len = packet->payload[s_offset++];

		  if((s_offset + alpn_len) <= tot_alpn_len) {
#ifdef DEBUG_TLS
		    printf("Client SSL [ALPN: %u]\n", alpn_len);
#endif

		    if((alpn_str_len+alpn_len+1) < (sizeof(alpn_str)-1)) {
		      if(alpn_str_len > 0) {
			alpn_str[alpn_str_len] = ',';
			alpn_str_len++;
		      }

		      for(alpn_i=0; alpn_i<alpn_len; alpn_i++)
			alpn_str[alpn_str_len+alpn_i] = packet->payload[s_offset+alpn_i];

		      s_offset += alpn_len, alpn_str_len += alpn_len;;
		    } else
		      break;
		  } else
		    break;
		} /* while */

		alpn_str[alpn_str_len] = '\0';

#ifdef DEBUG_TLS
		printf("Client SSL [ALPN: %s][len: %u]\n", alpn_str, alpn_str_len);
#endif
		if(flow->protos.tls_quic_stun.tls_quic.alpn == NULL)
		  flow->protos.tls_quic_stun.tls_quic.alpn = ndpi_strdup(alpn_str);
	      } else if(extension_id == 43 /* supported versions */) {
		u_int16_t s_offset = offset+extension_offset;
		u_int8_t version_len = packet->payload[s_offset];
		char version_str[256];
		u_int8_t version_str_len = 0;
		version_str[0] = 0;
#ifdef DEBUG_TLS
		printf("Client SSL [TLS version len: %u]\n", version_len);
#endif

		if(version_len == (extension_len-1)) {
		  u_int8_t j;

		  s_offset++;

		  // careful not to overflow and loop forever with u_int8_t
		  for(j=0; j+1<version_len; j += 2) {
		    u_int16_t tls_version = ntohs(*((u_int16_t*)&packet->payload[s_offset+j]));
		    u_int8_t unknown_tls_version;

#ifdef DEBUG_TLS
		    printf("Client SSL [TLS version: %s/0x%04X]\n",
			   ndpi_ssl_version2str(flow, tls_version, &unknown_tls_version), tls_version);
#endif

		    if((version_str_len+8) < sizeof(version_str)) {
		      int rc = snprintf(&version_str[version_str_len],
					sizeof(version_str) - version_str_len, "%s%s",
					(version_str_len > 0) ? "," : "",
					ndpi_ssl_version2str(flow, tls_version, &unknown_tls_version));
		      if(rc <= 0)
			break;
		      else
			version_str_len += rc;
		    }
		  }
		if(flow->protos.tls_quic_stun.tls_quic.tls_supported_versions == NULL)
		  flow->protos.tls_quic_stun.tls_quic.tls_supported_versions = ndpi_strdup(version_str);
		}
	      } else if(extension_id == 65486 /* encrypted server name */) {
		/*
		   - https://tools.ietf.org/html/draft-ietf-tls-esni-06
		   - https://blog.cloudflare.com/encrypted-sni/
		*/
		u_int16_t e_offset = offset+extension_offset;
		u_int16_t initial_offset = e_offset;
		u_int16_t e_sni_len, cipher_suite = ntohs(*((u_int16_t*)&packet->payload[e_offset]));

		flow->protos.tls_quic_stun.tls_quic.encrypted_sni.cipher_suite = cipher_suite;

		e_offset += 2; /* Cipher suite len */

		/* Key Share Entry */
		e_offset += 2; /* Group */
		e_offset +=  ntohs(*((u_int16_t*)&packet->payload[e_offset])) + 2; /* Lenght */

		if((e_offset+4) < packet->payload_packet_len) {
		  /* Record Digest */
		  e_offset +=  ntohs(*((u_int16_t*)&packet->payload[e_offset])) + 2; /* Lenght */

		  if((e_offset+4) < packet->payload_packet_len) {
		    e_sni_len = ntohs(*((u_int16_t*)&packet->payload[e_offset]));
		    e_offset += 2;

		    if((e_offset+e_sni_len-extension_len-initial_offset) >= 0 &&
		        e_offset+e_sni_len < packet->payload_packet_len) {
#ifdef DEBUG_ENCRYPTED_SNI
		      printf("Client SSL [Encrypted Server Name len: %u]\n", e_sni_len);
#endif

		      if(flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni == NULL) {
			flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni = (char*)ndpi_malloc(e_sni_len*2+1);

			if(flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni) {
			  u_int16_t i, off;

			  for(i=e_offset, off=0; i<(e_offset+e_sni_len); i++) {
			    int rc = sprintf(&flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni[off], "%02X", packet->payload[i] & 0XFF);

			    if(rc <= 0) {
			      flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni[off] = '\0';
			      break;
			    } else
			      off += rc;
			  }
			}
		      }
		    }
		  }
		}
	      } else if(extension_id == 65445 || /* QUIC transport parameters (drafts version) */
		        extension_id == 57) { /* QUIC transport parameters (final version) */
		u_int16_t s_offset = offset+extension_offset;
		uint16_t final_offset;
		int using_var_int = is_version_with_var_int_transport_params(quic_version);

		if(!using_var_int) {
		  if(s_offset+1 >= total_len) {
		    final_offset = 0; /* Force skipping extension */
		  } else {
		    u_int16_t seq_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		    s_offset += 2;
	            final_offset = MIN(total_len, s_offset + seq_len);
		  }
		} else {
	          final_offset = MIN(total_len, s_offset + extension_len);
		}

		while(s_offset < final_offset) {
		  u_int64_t param_type, param_len;

                  if(!using_var_int) {
		    if(s_offset+3 >= final_offset)
		      break;
		    param_type = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		    param_len = ntohs(*((u_int16_t*)&packet->payload[s_offset + 2]));
		    s_offset += 4;
		  } else {
		    if(s_offset >= final_offset ||
		       (s_offset + quic_len_buffer_still_required(packet->payload[s_offset])) >= final_offset)
		      break;
		    s_offset += quic_len(&packet->payload[s_offset], &param_type);

		    if(s_offset >= final_offset ||
		       (s_offset + quic_len_buffer_still_required(packet->payload[s_offset])) >= final_offset)
		      break;
		    s_offset += quic_len(&packet->payload[s_offset], &param_len);
		  }

#ifdef DEBUG_TLS
		  printf("Client SSL [QUIC TP: Param 0x%x Len %d]\n", (int)param_type, (int)param_len);
#endif
		  if(s_offset+param_len > final_offset)
		    break;

		  if(param_type==0x3129) {
#ifdef DEBUG_TLS
		      printf("UA [%.*s]\n", (int)param_len, &packet->payload[s_offset]);
#endif
		      http_process_user_agent(ndpi_struct, flow,
					      &packet->payload[s_offset], param_len);
		      break;
		  }
		  s_offset += param_len;
		}
	      }

	      extension_offset += extension_len; /* Move to the next extension */

#ifdef DEBUG_TLS
	      printf("Client SSL [extension_offset/len: %u/%u]\n", extension_offset, extension_len);
#endif
	    } /* while */

	    if(!invalid_ja3) {
	      int rc;

	    compute_ja3c:
	      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.tls_handshake_version);

	      for(i=0; i<ja3.num_cipher; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
			      (i > 0) ? "-" : "", ja3.cipher[i]);
		if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc; else break;
	      }

	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
	      if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc;

	      /* ********** */

	      for(i=0; i<ja3.num_tls_extension; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
			      (i > 0) ? "-" : "", ja3.tls_extension[i]);
		if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc; else break;
	      }

	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
	      if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc;

	      /* ********** */

	      for(i=0; i<ja3.num_elliptic_curve; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
			      (i > 0) ? "-" : "", ja3.elliptic_curve[i]);
		if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc; else break;
	      }

	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
	      if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc;

	      for(i=0; i<ja3.num_elliptic_curve_point_format; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
			      (i > 0) ? "-" : "", ja3.elliptic_curve_point_format[i]);
		if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc; else break;
	      }

#ifdef DEBUG_TLS
	      printf("[JA3] Client: %s \n", ja3_str);
#endif

	      ndpi_MD5Init(&ctx);
	      ndpi_MD5Update(&ctx, (const unsigned char *)ja3_str, strlen(ja3_str));
	      ndpi_MD5Final(md5_hash, &ctx);

	      for(i=0, j=0; i<16; i++) {
		rc = snprintf(&flow->protos.tls_quic_stun.tls_quic.ja3_client[j],
			      sizeof(flow->protos.tls_quic_stun.tls_quic.ja3_client)-j, "%02x",
			      md5_hash[i]);
		if(rc > 0) j += rc; else break;
	      }
	      
#ifdef DEBUG_TLS
	      printf("[JA3] Client: %s \n", flow->protos.tls_quic_stun.tls_quic.ja3_client);
#endif
	      
	      if(ndpi_struct->malicious_ja3_automa.ac_automa != NULL) {
		u_int16_t rc1 = ndpi_match_string(ndpi_struct->malicious_ja3_automa.ac_automa,
						  flow->protos.tls_quic_stun.tls_quic.ja3_client);
		
		if(rc1 > 0)
		  ndpi_set_risk(flow, NDPI_MALICIOUS_JA3);
	      }	      
	    }

	    /* Before returning to the caller we need to make a final check */
	    if((flow->protos.tls_quic_stun.tls_quic.ssl_version >= 0x0303) /* >= TLSv1.2 */
	       && (flow->protos.tls_quic_stun.tls_quic.alpn == NULL) /* No ALPN */) {
	      ndpi_set_risk(flow, NDPI_TLS_NOT_CARRYING_HTTPS);
	    }

	    /* Suspicious Domain Fronting:
	       https://github.com/SixGenInc/Noctilucent/blob/master/docs/ */
	    if(flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni &&
	       flow->protos.tls_quic_stun.tls_quic.client_requested_server_name[0] != '\0') {
	      ndpi_set_risk(flow, NDPI_TLS_SUSPICIOUS_ESNI_USAGE);
	    }

	    /* Add check for missing SNI */
	    if((flow->protos.tls_quic_stun.tls_quic.client_requested_server_name[0] == 0)
	       && (flow->protos.tls_quic_stun.tls_quic.ssl_version >= 0x0302) /* TLSv1.1 */
	       && (flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni == NULL) /* No ESNI */
	       ) {
	      /* This is a bit suspicious */
	      ndpi_set_risk(flow, NDPI_TLS_MISSING_SNI);
	    }

	    return(2 /* Client Certificate */);
	  } else {
#ifdef DEBUG_TLS
	    printf("[TLS] Client: too short [%u vs %u]\n",
		   (extensions_len+offset), total_len);
#endif
	  }
	} else if(offset == total_len) {
	  /* SSL does not have extensions etc */
	  goto compute_ja3c;
	}
      } else {
#ifdef DEBUG_TLS
	printf("[JA3] Client: invalid length detected\n");
#endif
      }
    }
  }

  return(0); /* Not found */
}

/* **************************************** */

static void ndpi_search_tls_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

#ifdef DEBUG_TLS
  printf("==>> %s() %u [len: %u][version: %u]\n",
	 __FUNCTION__,
	 flow->guessed_host_protocol_id,
	 packet->payload_packet_len,
	 flow->protos.tls_quic_stun.tls_quic.ssl_version);
#endif

  if(packet->udp != NULL)
    ndpi_search_tls_udp(ndpi_struct, flow);
  else
    ndpi_search_tls_tcp(ndpi_struct, flow);
}

/* **************************************** */

void init_tls_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("TLS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_TLS,
				      ndpi_search_tls_wrapper,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;

  /* *************************************************** */

  ndpi_set_bitmask_protocol_detection("DTLS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DTLS,
				      ndpi_search_tls_wrapper,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
