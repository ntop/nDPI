/*
 * ssl.c
 *
 * Copyright (C) 2016-18 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SSL

#include "ndpi_api.h"

/* #define CERTIFICATE_DEBUG 1  */

#define NDPI_MAX_SSL_REQUEST_SIZE 10000

/* Skype.c */
extern u_int8_t is_skype_flow(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow);

/* **************************************** */

typedef struct MD5Context {
  uint32_t buf[4];
  uint32_t bits[2];
  unsigned char in[64];
} MD5_CTX;

/* **************************************** */

static int is_big_endian(void) {
  static const int n = 1;
  return ((char *) &n)[0] == 0;
}

static void byteReverse(unsigned char *buf, unsigned longs) {
  uint32_t t;

  // Forrest: MD5 expect LITTLE_ENDIAN, swap if BIG_ENDIAN
  if (is_big_endian()) {
    do {
      t = (uint32_t) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
	((unsigned) buf[1] << 8 | buf[0]);
      * (uint32_t *) buf = t;
      buf += 4;
    } while (--longs);
  }
}

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

#define MD5STEP(f, w, x, y, z, data, s)	\
  ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

// Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
// initialization constants.
static void MD5Init(MD5_CTX *ctx) {
  ctx->buf[0] = 0x67452301;
  ctx->buf[1] = 0xefcdab89;
  ctx->buf[2] = 0x98badcfe;
  ctx->buf[3] = 0x10325476;

  ctx->bits[0] = 0;
  ctx->bits[1] = 0;
}

static void MD5Transform(uint32_t buf[4], uint32_t const in[16]) {
  uint32_t a, b, c, d;

  a = buf[0];
  b = buf[1];
  c = buf[2];
  d = buf[3];

  MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
  MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
  MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
  MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
  MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
  MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
  MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
  MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
  MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
  MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
  MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
  MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
  MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
  MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
  MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
  MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

  MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
  MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
  MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
  MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
  MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
  MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
  MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
  MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
  MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
  MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
  MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
  MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
  MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
  MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
  MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
  MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

  MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
  MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
  MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
  MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
  MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
  MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
  MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
  MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
  MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
  MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
  MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
  MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
  MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
  MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
  MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
  MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

  MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
  MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
  MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
  MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
  MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
  MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
  MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
  MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
  MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
  MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
  MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
  MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
  MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
  MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
  MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
  MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}

static void MD5Update(MD5_CTX *ctx, unsigned char const *buf, unsigned len) {
  uint32_t t;

  t = ctx->bits[0];
  if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
    ctx->bits[1]++;
  ctx->bits[1] += len >> 29;

  t = (t >> 3) & 0x3f;

  if (t) {
    unsigned char *p = (unsigned char *) ctx->in + t;

    t = 64 - t;
    if (len < t) {
      memcpy(p, buf, len);
      return;
    }
    memcpy(p, buf, t);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    buf += t;
    len -= t;
  }

  while (len >= 64) {
    memcpy(ctx->in, buf, 64);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    buf += 64;
    len -= 64;
  }

  memcpy(ctx->in, buf, len);
}

static void MD5Final(unsigned char digest[16], MD5_CTX *ctx) {
  unsigned count;
  unsigned char *p;
  uint32_t *c = (uint32_t*)ctx->in;

  count = (ctx->bits[0] >> 3) & 0x3F;

  p = ctx->in + count;
  *p++ = 0x80;
  count = 64 - 1 - count;
  if (count < 8) {
    memset(p, 0, count);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    memset(ctx->in, 0, 56);
  } else {
    memset(p, 0, count - 8);
  }
  byteReverse(ctx->in, 14);

  c[14] = ctx->bits[0];
  c[15] = ctx->bits[1];

  MD5Transform(ctx->buf, (uint32_t *) ctx->in);
  byteReverse((unsigned char *) ctx->buf, 4);
  memcpy(digest, ctx->buf, 16);
  memset((char *) ctx, 0, sizeof(*ctx));
}

/* **************************************** */

static u_int32_t ndpi_ssl_refine_master_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						 struct ndpi_flow_struct *flow, u_int32_t protocol)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if(((flow->l4.tcp.ssl_seen_client_cert == 1) && (flow->protos.stun_ssl.ssl.client_certificate[0] != '\0'))
     || ((flow->l4.tcp.ssl_seen_server_cert == 1) && (flow->protos.stun_ssl.ssl.server_certificate[0] != '\0'))
     || (flow->host_server_name[0] != '\0'))
    protocol = NDPI_PROTOCOL_SSL;
  else
    protocol =  NDPI_PROTOCOL_SSL_NO_CERT;

  if(packet->tcp != NULL) {
    switch(protocol) {

    case NDPI_PROTOCOL_SSL:
    case NDPI_PROTOCOL_SSL_NO_CERT:
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

  return protocol;
}

static void ndpi_int_ssl_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow, u_int32_t protocol)
{
  if((protocol != NDPI_PROTOCOL_SSL)
     && (protocol != NDPI_PROTOCOL_SSL_NO_CERT)) {
    ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_UNKNOWN);
  } else {
    protocol = ndpi_ssl_refine_master_protocol(ndpi_struct, flow, protocol);
    ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_UNKNOWN);
  }
}

/* Can't call libc functions from kernel space, define some stub instead */

#define ndpi_isalpha(ch) (((ch) >= 'a' && (ch) <= 'z') || ((ch) >= 'A' && (ch) <= 'Z'))
#define ndpi_isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#define ndpi_isspace(ch) (((ch) >= '\t' && (ch) <= '\r') || ((ch) == ' '))
#define ndpi_isprint(ch) ((ch) >= 0x20 && (ch) <= 0x7e)
#define ndpi_ispunct(ch) (((ch) >= '!' && (ch) <= '/') ||	\
			  ((ch) >= ':' && (ch) <= '@') ||	\
			  ((ch) >= '[' && (ch) <= '`') ||	\
			  ((ch) >= '{' && (ch) <= '~'))

static void stripCertificateTrailer(char *buffer, int buffer_len) {

  int i, is_puny;

  //  printf("->%s<-\n", buffer);

  for(i = 0; i < buffer_len; i++) {
    // printf("%c [%d]\n", buffer[i], buffer[i]);

    if((buffer[i] != '.')
       && (buffer[i] != '-')
       && (buffer[i] != '_')
       && (buffer[i] != '*')
       && (!ndpi_isalpha(buffer[i]))
       && (!ndpi_isdigit(buffer[i]))) {
      buffer[i] = '\0';
      buffer_len = i;
      break;
    }
  }

  /* check for punycode encoding */
  is_puny = ndpi_check_punycode_string(buffer, buffer_len);

  // not a punycode string - need more checks
  if(is_puny == 0) {

    if(i > 0) i--;

    while(i > 0) {
      if(!ndpi_isalpha(buffer[i])) {
	buffer[i] = '\0';
	buffer_len = i;
	i--;
      } else
	break;
    }

    for(i = buffer_len; i > 0; i--) {
      if(buffer[i] == '.') break;
      else if(ndpi_isdigit(buffer[i]))
	buffer[i] = '\0', buffer_len = i;
    }
  }
}

/* https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967 */

#define JA3_STR_LEN 1024
#define MAX_NUM_JA3  128

struct ja3_info {
  u_int16_t ssl_version;
  u_int16_t num_cipher, cipher[MAX_NUM_JA3];
  u_int16_t num_ssl_extension, ssl_extension[MAX_NUM_JA3];
  u_int16_t num_elliptic_curve, elliptic_curve[MAX_NUM_JA3];
  u_int8_t num_elliptic_curve_point_format, elliptic_curve_point_format[MAX_NUM_JA3];
};

/* **************************************** */

/* code fixes courtesy of Alexsandro Brahm <alex@digistar.com.br> */
int getSSLcertificate(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow,
		      char *buffer, int buffer_len) {
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ja3_info ja3;
  u_int8_t invalid_ja3 = 0;
  u_int16_t ssl_version = (packet->payload[1] << 8) + packet->payload[2], ja3_str_len;
  char ja3_str[JA3_STR_LEN];
  MD5_CTX ctx;
  u_char md5_hash[16];

  flow->protos.stun_ssl.ssl.ssl_version = ssl_version;
  
  memset(&ja3, 0, sizeof(ja3));

#ifdef CERTIFICATE_DEBUG
  {
    u_int16_t ssl_len = (packet->payload[3] << 8) + packet->payload[4];

    printf("SSL Record [version: %u][len: %u]\n", ssl_version, ssl_len);
  }
#endif

  /*
    Nothing matched so far: let's decode the certificate with some heuristics
    Patches courtesy of Denys Fedoryshchenko <nuclearcat@nuclearcat.com>
  */
  if(packet->payload[0] == 0x16 /* Handshake */) {
    u_int16_t total_len  = (packet->payload[3] << 8) + packet->payload[4] + 5 /* SSL Header */;
    u_int8_t handshake_protocol = packet->payload[5]; /* handshake protocol a bit misleading, it is message type according TLS specs */

    memset(buffer, 0, buffer_len);

    /* Truncate total len, search at least in incomplete packet */
    if(total_len > packet->payload_packet_len)
      total_len = packet->payload_packet_len;

    /* At least "magic" 3 bytes, null for string end, otherwise no need to waste cpu cycles */
    if(total_len > 4) {
      int i;

#ifdef CERTIFICATE_DEBUG
      printf("SSL [len: %u][handshake_protocol: %02X]\n", packet->payload_packet_len, handshake_protocol);
#endif

      if((handshake_protocol == 0x02)
	 || (handshake_protocol == 0xb) /* Server Hello and Certificate message types are interesting for us */) {
	u_int num_found = 0;
	u_int16_t  ssl_version = ntohs(*((u_int16_t*)&packet->payload[9]));

	ja3.ssl_version = ssl_version;

	if(handshake_protocol == 0x02) {
	  u_int16_t offset = 43, extension_len, j;
	  u_int8_t  session_id_len = packet->payload[43];

	  offset += session_id_len+1;

	  ja3.num_cipher = 1, ja3.cipher[0] = ntohs(*((u_int16_t*)&packet->payload[offset]));
	  flow->protos.stun_ssl.ssl.server_unsafe_cipher = ndpi_is_safe_ssl_cipher(ja3.cipher[0]);
	  flow->protos.stun_ssl.ssl.server_cipher = ja3.cipher[0];
	  
#ifdef CERTIFICATE_DEBUG
	  printf("SSL [server][session_id_len: %u][cipher: %04X]\n", session_id_len, ja3.cipher[0]);
#endif

	  offset += 2 + 1;
	  extension_len = ntohs(*((u_int16_t*)&packet->payload[offset]));

#ifdef CERTIFICATE_DEBUG
	  printf("SSL [server][extension_len: %u]\n", extension_len);
#endif
	  offset += 2;

	  for(i=0; i<extension_len; ) {
	    u_int16_t id, len;

	    if(offset >= (packet->payload_packet_len+4)) break;

	    id  = ntohs(*((u_int16_t*)&packet->payload[offset]));
	    len = ntohs(*((u_int16_t*)&packet->payload[offset+2]));

	    if(ja3.num_ssl_extension < MAX_NUM_JA3)
	      ja3.ssl_extension[ja3.num_ssl_extension++] = id;

#ifdef CERTIFICATE_DEBUG
	    printf("SSL [server][extension_id: %u]\n", id);
#endif

	    i += 4 + len, offset += 4 + len;
	  }

	  ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.ssl_version);

	  for(i=0; i<ja3.num_cipher; i++)
	    ja3_str_len += snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.cipher[i]);

	  ja3_str_len += snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");

	  /* ********** */

	  for(i=0; i<ja3.num_ssl_extension; i++)
	    ja3_str_len += snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.ssl_extension[i]);

#ifdef CERTIFICATE_DEBUG
	  printf("SSL [server] %s\n", ja3_str);
#endif
	  
#ifdef CERTIFICATE_DEBUG
	  printf("[JA3] Server: %s \n", ja3_str);
#endif
	  
	  MD5Init(&ctx);
	  MD5Update(&ctx, (const unsigned char *)ja3_str, strlen(ja3_str));
	  MD5Final(md5_hash, &ctx);
	  
	  for(i=0, j=0; i<16; i++)
	    j += snprintf(&flow->protos.stun_ssl.ssl.ja3_server[j],
			  sizeof(flow->protos.stun_ssl.ssl.ja3_server)-j, "%02x", md5_hash[i]);
	  
#ifdef CERTIFICATE_DEBUG
	  printf("[JA3] Server: %s \n", flow->protos.stun_ssl.ssl.ja3_server);
#endif
	  
	  flow->l4.tcp.ssl_seen_server_cert = 1;
	} else
	  flow->l4.tcp.ssl_seen_certificate = 1;

	/* Check after handshake protocol header (5 bytes) and message header (4 bytes) */
	for(i = 9; i < packet->payload_packet_len-3; i++) {
	  if(((packet->payload[i] == 0x04) && (packet->payload[i+1] == 0x03) && (packet->payload[i+2] == 0x0c))
	     || ((packet->payload[i] == 0x04) && (packet->payload[i+1] == 0x03) && (packet->payload[i+2] == 0x13))
	     || ((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x03))) {
	    u_int8_t server_len = packet->payload[i+3];

	    if(packet->payload[i] == 0x55) {
	      num_found++;

	      if(num_found != 2) continue;
	    }

	    if(server_len+i+3 < packet->payload_packet_len) {
	      char *server_name = (char*)&packet->payload[i+4];
	      u_int8_t begin = 0, len, j, num_dots;

	      while(begin < server_len) {
		if(!ndpi_isprint(server_name[begin]))
		  begin++;
		else
		  break;
	      }

	      // len = ndpi_min(server_len-begin, buffer_len-1);
	      len = buffer_len-1;
	      strncpy(buffer, &server_name[begin], len);
	      buffer[len] = '\0';

	      /* We now have to check if this looks like an IP address or host name */
	      for(j=0, num_dots = 0; j<len; j++) {
		if(!ndpi_isprint((buffer[j]))) {
		  num_dots = 0; /* This is not what we look for */
		  break;
		} else if(buffer[j] == '.') {
		  num_dots++;
		  if(num_dots >=1) break;
		}
	      }

	      if(num_dots >= 1) {
		if(!ndpi_struct->disable_metadata_export) {
		  stripCertificateTrailer(buffer, buffer_len);
		  snprintf(flow->protos.stun_ssl.ssl.server_certificate,
			   sizeof(flow->protos.stun_ssl.ssl.server_certificate), "%s", buffer);
		}

		return(1 /* Server Certificate */);
	      }
	    }
	  }
	}
      } else if(handshake_protocol == 0x01 /* Client Hello */) {
	u_int offset, base_offset = 43;

	if(base_offset + 2 <= packet->payload_packet_len) {
	  u_int16_t session_id_len = packet->payload[base_offset];
	  u_int16_t  ssl_version   = ntohs(*((u_int16_t*)&packet->payload[9]));

	  ja3.ssl_version = ssl_version;

	  if((session_id_len+base_offset+2) <= total_len) {
	    u_int16_t cipher_len =  packet->payload[session_id_len+base_offset+2] + (packet->payload[session_id_len+base_offset+1] << 8);
	    u_int16_t i, cipher_offset = base_offset + session_id_len + 3;

#ifdef CERTIFICATE_DEBUG
	    printf("Client SSL [client cipher_len: %u]\n", cipher_len);
#endif

	    if((cipher_offset+cipher_len) <= total_len) {
	      for(i=0; i<cipher_len;) {
		u_int16_t *id = (u_int16_t*)&packet->payload[cipher_offset+i];
		
#ifdef CERTIFICATE_DEBUG
		printf("Client SSL [cipher suite: %u] [%u/%u]\n", ntohs(*id), i, cipher_len);
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
#ifdef CERTIFICATE_DEBUG
		    printf("Client SSL Invalid cipher %u\n", ja3.num_cipher);
#endif
		  }
		}
		
		i += 2;
	      }
	    } else {
	      invalid_ja3 = 1;
#ifdef CERTIFICATE_DEBUG
	      printf("Client SSL Invalid len %u vs %u\n", (cipher_offset+cipher_len), total_len);
#endif		    
	    }
	    
	    offset = base_offset + session_id_len + cipher_len + 2;

	    flow->l4.tcp.ssl_seen_client_cert = 1;

	    if(offset < total_len) {
	      u_int16_t compression_len;
	      u_int16_t extensions_len;

	      offset++;
	      compression_len = packet->payload[offset];
	      offset++;

#ifdef CERTIFICATE_DEBUG
	      printf("Client SSL [compression_len: %u]\n", compression_len);
#endif

	      // offset += compression_len + 3;
	      offset += compression_len;

	      if(offset < total_len) {
		extensions_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
		offset += 2;

#ifdef CERTIFICATE_DEBUG
		printf("Client SSL [extensions_len: %u]\n", extensions_len);
#endif

		if((extensions_len+offset) <= total_len) {
		  /* Move to the first extension
		     Type is u_int to avoid possible overflow on extension_len addition */
		  u_int extension_offset = 0;
		  u_int32_t md5h[4], j;

		  while(extension_offset < extensions_len) {
		    u_int16_t extension_id, extension_len, extn_off = offset+extension_offset;

		    extension_id = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
		    extension_offset += 2;

		    extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
		    extension_offset += 2;

#ifdef CERTIFICATE_DEBUG
		    printf("Client SSL [extension_id: %u][extension_len: %u]\n", extension_id, extension_len);
#endif

		    if((extension_id == 0) || (packet->payload[extn_off] != packet->payload[extn_off+1])) {
		      /* Skip GREASE */

		      if(ja3.num_ssl_extension < MAX_NUM_JA3)
			ja3.ssl_extension[ja3.num_ssl_extension++] = extension_id;
		      else {
			invalid_ja3 = 1;
#ifdef CERTIFICATE_DEBUG
			printf("Client SSL Invalid extensions %u\n", ja3.num_ssl_extension);
#endif
		      }
		    }

		    if(extension_id == 0 /* server name */) {
		      u_int16_t len;

		      len = (packet->payload[offset+extension_offset+3] << 8) + packet->payload[offset+extension_offset+4];
		      len = (u_int)ndpi_min(len, buffer_len-1);
		      strncpy(buffer, (char*)&packet->payload[offset+extension_offset+5], len);
		      buffer[len] = '\0';

		      stripCertificateTrailer(buffer, buffer_len);

		      if(!ndpi_struct->disable_metadata_export) {
			snprintf(flow->protos.stun_ssl.ssl.client_certificate,
				 sizeof(flow->protos.stun_ssl.ssl.client_certificate), "%s", buffer);
		      }
		    } else if(extension_id == 10 /* supported groups */) {
		      u_int16_t i, s_offset = offset+extension_offset + 2;

#ifdef CERTIFICATE_DEBUG
		      printf("Client SSL [EllipticCurveGroups: len=%u]\n", extension_len);
#endif

		      if((s_offset+extension_len-2) <= total_len) {
			for(i=0; i<extension_len-2;) {
			  u_int16_t s_group = ntohs(*((u_int16_t*)&packet->payload[s_offset+i]));
			
#ifdef CERTIFICATE_DEBUG
			  printf("Client SSL [EllipticCurve: %u]\n", s_group);
#endif
			  if((s_group == 0) || (packet->payload[s_offset+i] != packet->payload[s_offset+i+1])) {
			    /* Skip GREASE */
			    if(ja3.num_elliptic_curve < MAX_NUM_JA3)
			      ja3.elliptic_curve[ja3.num_elliptic_curve++] = s_group;
			    else {			      
			      invalid_ja3 = 1;
#ifdef CERTIFICATE_DEBUG
			      printf("Client SSL Invalid num elliptic %u\n", ja3.num_elliptic_curve);
#endif
			    }
			  }

			  i += 2;
			}
		      } else {
			invalid_ja3 = 1;
#ifdef CERTIFICATE_DEBUG
			printf("Client SSL Invalid len %u vs %u\n", (s_offset+extension_len-1), total_len);
#endif
		      }		     
		    } else if(extension_id == 11 /* ec_point_formats groups */) {
		      u_int16_t i, s_offset = offset+extension_offset + 1;

#ifdef CERTIFICATE_DEBUG
		      printf("Client SSL [EllipticCurveFormat: len=%u]\n", extension_len);
#endif
		      if((s_offset+extension_len) < total_len) {
			for(i=0; i<extension_len-1;i++) {
			  u_int8_t s_group = packet->payload[s_offset+i];
			  
#ifdef CERTIFICATE_DEBUG
			  printf("Client SSL [EllipticCurveFormat: %u]\n", s_group);
#endif
			  
			  if(ja3.num_elliptic_curve_point_format < MAX_NUM_JA3)
			    ja3.elliptic_curve_point_format[ja3.num_elliptic_curve_point_format++] = s_group;
			  else {
			    invalid_ja3 = 1;
#ifdef CERTIFICATE_DEBUG
			    printf("Client SSL Invalid num elliptic %u\n", ja3.num_elliptic_curve_point_format);
#endif
			  }
			}
		      } else {
			invalid_ja3 = 1;
#ifdef CERTIFICATE_DEBUG
			printf("Client SSL Invalid len %u vs %u\n", s_offset+extension_len, total_len);
#endif
		      }
		    }
		    
		    extension_offset += extension_len;

#ifdef CERTIFICATE_DEBUG
		    printf("Client SSL [extension_offset/len: %u/%u]\n", extension_offset, extension_len);
#endif
		  } /* while */

		  if(!invalid_ja3) {
		    ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.ssl_version);
		    
		    for(i=0; i<ja3.num_cipher; i++) {
		      ja3_str_len += snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
					      (i > 0) ? "-" : "", ja3.cipher[i]);
		    }
		    
		    ja3_str_len += snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
		    
		    /* ********** */
		    
		    for(i=0; i<ja3.num_ssl_extension; i++)
		      ja3_str_len += snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
					      (i > 0) ? "-" : "", ja3.ssl_extension[i]);
		    
		    ja3_str_len += snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
		    
		    /* ********** */
		    
		    for(i=0; i<ja3.num_elliptic_curve; i++)
		      ja3_str_len += snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
					      (i > 0) ? "-" : "", ja3.elliptic_curve[i]);
		    
		    ja3_str_len += snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
		    
		    for(i=0; i<ja3.num_elliptic_curve_point_format; i++)
		      ja3_str_len += snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
					      (i > 0) ? "-" : "", ja3.elliptic_curve_point_format[i]);

#ifdef CERTIFICATE_DEBUG
		    printf("[JA3] Client: %s \n", ja3_str);
#endif

		    MD5Init(&ctx);
		    MD5Update(&ctx, (const unsigned char *)ja3_str, strlen(ja3_str));
		    MD5Final(md5_hash, &ctx);

		    for(i=0, j=0; i<16; i++)
		      j += snprintf(&flow->protos.stun_ssl.ssl.ja3_client[j],
				    sizeof(flow->protos.stun_ssl.ssl.ja3_client)-j, "%02x", md5_hash[i]);

#ifdef CERTIFICATE_DEBUG
		    printf("[JA3] Client: %s \n", flow->protos.stun_ssl.ssl.ja3_client);
#endif
		  }
		  
		  return(2 /* Client Certificate */);
		}
	      }
	    }
	  }
	}
      }
    }
  }

  return(0); /* Not found */
}

void getSSLorganization(struct ndpi_detection_module_struct *ndpi_struct,
			struct ndpi_flow_struct *flow,
			char *buffer, int buffer_len) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->payload[0] != 0x16 /* Handshake */)
    return;

  u_int16_t total_len  = (packet->payload[3] << 8) + packet->payload[4] + 5 /* SSL Header */;
  u_int8_t handshake_protocol = packet->payload[5]; /* handshake protocol a bit misleading, it is message type according TLS specs */

  if(handshake_protocol != 0x02 && handshake_protocol != 0xb /* Server Hello and Certificate message types are interesting for us */)
    return;

  /* Truncate total len, search at least in incomplete packet */
  if(total_len > packet->payload_packet_len)
    total_len = packet->payload_packet_len;

  memset(buffer, 0, buffer_len);

  /* Check after handshake protocol header (5 bytes) and message header (4 bytes) */
  u_int num_found = 0;
  u_int i, j;
  for(i = 9; i < packet->payload_packet_len-4; i++) {
    /* Organization OID: 2.5.4.10 */
    if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x0a)) {
      u_int8_t type_tag = packet->payload[i+3]; // 0x0c: utf8string / 0x13: printable_string
      u_int8_t server_len = packet->payload[i+4];

      num_found++;
      /* what we want is subject certificate, so we bypass the issuer certificate */
      if(num_found != 2) continue;

      // packet is truncated... further inspection is not needed
      if(i+4+server_len >= packet->payload_packet_len) {
	break;
      }

      char *server_org = (char*)&packet->payload[i+5];

      u_int len = (u_int)ndpi_min(server_len, buffer_len-1);
      strncpy(buffer, server_org, len);
      buffer[len] = '\0';

      // check if organization string are all printable
      u_int8_t is_printable = 1;
      for (j = 0; j < len; j++) {
	if(!ndpi_isprint(buffer[j])) {
	  is_printable = 0;
	  break;
	}
      }

      if(is_printable == 1) {
	snprintf(flow->protos.stun_ssl.ssl.server_organization,
		 sizeof(flow->protos.stun_ssl.ssl.server_organization), "%s", buffer);
#ifdef CERTIFICATE_DEBUG
	printf("Certificate organization: %s\n", flow->protos.stun_ssl.ssl.server_organization);
#endif
      }
    }
  }
}


int sslTryAndRetrieveServerCertificate(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  /* consider only specific SSL packets (handshake) */
  if((packet->payload_packet_len > 9) && (packet->payload[0] == 0x16)) {
    char certificate[64];
    char organization[64];
    int rc;

    certificate[0] = '\0';
    rc = getSSLcertificate(ndpi_struct, flow, certificate, sizeof(certificate));
    packet->ssl_certificate_num_checks++;
    if(rc > 0) {
      // try fetch server organization once server certificate is found
      organization[0] = '\0';
      getSSLorganization(ndpi_struct, flow, organization, sizeof(organization));

      packet->ssl_certificate_detected++;
      if((flow->l4.tcp.ssl_seen_server_cert == 1) && (flow->protos.stun_ssl.ssl.server_certificate[0] != '\0'))
        /* 0 means we're done processing extra packets (since we found what we wanted) */
        return 0;
    }
    /* Client hello, Server Hello, and certificate packets probably all checked in this case */
    if((packet->ssl_certificate_num_checks >= 3)
	&& (flow->l4.tcp.seen_syn)
	&& (flow->l4.tcp.seen_syn_ack)
	&& (flow->l4.tcp.seen_ack) /* We have seen the 3-way handshake */)
      {
	/* We're done processing extra packets since we've probably checked all possible cert packets */
	return 0;
      }
  }
  /* 1 means keep looking for more packets */
  return 1;
}

void sslInitExtraPacketProcessing(int caseNum, struct ndpi_flow_struct *flow) {
  flow->check_extra_packets = 1;
  /* 0 is the case for waiting for the server certificate */
  if(caseNum == 0) {
    /* At most 7 packets should almost always be enough to find the server certificate if it's there */
    flow->max_extra_packets_to_check = 7;
    flow->extra_packets_func = sslTryAndRetrieveServerCertificate;
  }
}

int sslDetectProtocolFromCertificate(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if((packet->payload_packet_len > 9)
     && (packet->payload[0] == 0x16 /* consider only specific SSL packets (handshake) */)) {
    if((packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
       || (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_SSL)) {
      char certificate[64];
      int rc;

      certificate[0] = '\0';
      rc = getSSLcertificate(ndpi_struct, flow, certificate, sizeof(certificate));
      packet->ssl_certificate_num_checks++;

      if(rc > 0) {
	packet->ssl_certificate_detected++;
#ifdef CERTIFICATE_DEBUG
	NDPI_LOG_DBG2(ndpi_struct, "***** [SSL] %s\n", certificate);
#endif
	ndpi_protocol_match_result ret_match;
	u_int32_t subproto = ndpi_match_host_subprotocol(ndpi_struct, flow, certificate,
							 strlen(certificate),
							 &ret_match,
							 NDPI_PROTOCOL_SSL);

	if(subproto != NDPI_PROTOCOL_UNKNOWN) {
	  /* If we've detected the subprotocol from client certificate but haven't had a chance
	   * to see the server certificate yet, set up extra packet processing to wait
	   * a few more packets. */
	  if(((flow->l4.tcp.ssl_seen_client_cert == 1) && (flow->protos.stun_ssl.ssl.client_certificate[0] != '\0'))
	     && ((flow->l4.tcp.ssl_seen_server_cert != 1) && (flow->protos.stun_ssl.ssl.server_certificate[0] == '\0'))) {
	    sslInitExtraPacketProcessing(0, flow);
	  }

	  ndpi_set_detected_protocol(ndpi_struct, flow, subproto,
				     ndpi_ssl_refine_master_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SSL));
	  return(rc); /* Fix courtesy of Gianluca Costa <g.costa@xplico.org> */
	}

	if(ndpi_is_ssl_tor(ndpi_struct, flow, certificate) != 0)
	  return(rc);
      }

      if(((packet->ssl_certificate_num_checks >= 3)
	  && flow->l4.tcp.seen_syn
	  && flow->l4.tcp.seen_syn_ack
	  && flow->l4.tcp.seen_ack /* We have seen the 3-way handshake */)
	 || ((flow->l4.tcp.ssl_seen_certificate == 1)
	     && (flow->l4.tcp.ssl_seen_server_cert == 1)
	     && (flow->protos.stun_ssl.ssl.server_certificate[0] != '\0'))
	 /* || ((flow->l4.tcp.ssl_seen_client_cert == 1) && (flow->protos.stun_ssl.ssl.client_certificate[0] != '\0')) */
	 ) {
	ndpi_int_ssl_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SSL);
      }
    }
  }
  return(0);
}

static void ssl_mark_and_payload_search_for_other_protocols(struct ndpi_detection_module_struct
							    *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t a;
  u_int32_t end;

  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_UNENCRYPTED_JABBER) != 0)
    goto check_for_ssl_payload;

  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, NDPI_PROTOCOL_OSCAR) != 0)
    goto check_for_ssl_payload;
  else
    goto no_check_for_ssl_payload;

 check_for_ssl_payload:
  end = packet->payload_packet_len - 20;
  for (a = 5; a < end; a++) {

    if(packet->payload[a] == 't') {
      if(memcmp(&packet->payload[a], "talk.google.com", 15) == 0) {
	if(NDPI_COMPARE_PROTOCOL_TO_BITMASK
	   (ndpi_struct->detection_bitmask, NDPI_PROTOCOL_UNENCRYPTED_JABBER) != 0) {
	  NDPI_LOG_INFO(ndpi_struct, "found ssl jabber unencrypted\n");
	  ndpi_int_ssl_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNENCRYPTED_JABBER);
	  return;
	}
      }
    }

    if(packet->payload[a] == 'A' || packet->payload[a] == 'k' || packet->payload[a] == 'c'
       || packet->payload[a] == 'h') {
      if(((a + 19) < packet->payload_packet_len && memcmp(&packet->payload[a], "America Online Inc.", 19) == 0)
	 //                        || (end - c > 3 memcmp (&packet->payload[c],"AOL", 3) == 0 )
	 //                        || (end - c > 7 && memcmp (&packet->payload[c], "AOL LLC", 7) == 0)
	 || ((a + 15) < packet->payload_packet_len && memcmp(&packet->payload[a], "kdc.uas.aol.com", 15) == 0)
	 || ((a + 14) < packet->payload_packet_len && memcmp(&packet->payload[a], "corehc@aol.net", 14) == 0)
	 || ((a + 41) < packet->payload_packet_len
	     && memcmp(&packet->payload[a], "http://crl.aol.com/AOLMSPKI/aolServerCert", 41) == 0)
	 || ((a + 28) < packet->payload_packet_len
	     && memcmp(&packet->payload[a], "http://ocsp.web.aol.com/ocsp", 28) == 0)
	 || ((a + 32) < packet->payload_packet_len
	     && memcmp(&packet->payload[a], "http://pki-info.aol.com/AOLMSPKI", 32) == 0)) {
	NDPI_LOG_INFO(ndpi_struct, "found OSCAR SERVER SSL DETECTED\n");

	if(flow->dst != NULL && packet->payload_packet_len > 75) {
	  memcpy(flow->dst->oscar_ssl_session_id, &packet->payload[44], 32);
	  flow->dst->oscar_ssl_session_id[32] = '\0';
	  flow->dst->oscar_last_safe_access_time = packet->tick_timestamp;
	}

	ndpi_int_ssl_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_OSCAR);
	return;
      }
    }

    if(packet->payload[a] == 'm' || packet->payload[a] == 's') {
      if((a + 21) < packet->payload_packet_len &&
	 (memcmp(&packet->payload[a], "my.screenname.aol.com", 21) == 0
	  || memcmp(&packet->payload[a], "sns-static.aolcdn.com", 21) == 0)) {
	NDPI_LOG_DBG(ndpi_struct, "found OSCAR SERVER SSL DETECTED\n");
	ndpi_int_ssl_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_OSCAR);
	return;
      }
    }
  }

 no_check_for_ssl_payload:
  if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
    NDPI_LOG_DBG(ndpi_struct, "found ssl connection\n");
    sslDetectProtocolFromCertificate(ndpi_struct, flow);

    if(!packet->ssl_certificate_detected
       && (!(flow->l4.tcp.ssl_seen_client_cert && flow->l4.tcp.ssl_seen_server_cert))) {
      /* SSL without certificate (Skype, Ultrasurf?) */
      NDPI_LOG_INFO(ndpi_struct, "found ssl NO_CERT\n");
      ndpi_int_ssl_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SSL_NO_CERT);
    } else if(packet->ssl_certificate_num_checks >= 3) {
      NDPI_LOG_INFO(ndpi_struct, "found ssl\n");
      ndpi_int_ssl_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SSL);
    }
  }
}


static u_int8_t ndpi_search_sslv3_direction1(struct ndpi_detection_module_struct *ndpi_struct,
					     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if((packet->payload_packet_len >= 5)
     && ((packet->payload[0] == 0x16) || packet->payload[0] == 0x17)
     && (packet->payload[1] == 0x03)
     && ((packet->payload[2] == 0x00) || (packet->payload[2] == 0x01) ||
         (packet->payload[2] == 0x02) || (packet->payload[2] == 0x03))) {
    u_int32_t temp;
    NDPI_LOG_DBG2(ndpi_struct, "search sslv3\n");
    // SSLv3 Record
    if(packet->payload_packet_len >= 1300) {
      return 1;
    }
    temp = ntohs(get_u_int16_t(packet->payload, 3)) + 5;
    NDPI_LOG_DBG2(ndpi_struct, "temp = %u\n", temp);
    if(packet->payload_packet_len == temp
       || (temp < packet->payload_packet_len && packet->payload_packet_len > 500)) {
      return 1;
    }

    if(packet->payload_packet_len < temp && temp < 5000 && packet->payload_packet_len > 9) {
      /* the server hello may be split into small packets */
      u_int32_t cert_start;

      NDPI_LOG_DBG2(ndpi_struct,
		    "maybe SSLv3 server hello split into smaller packets\n");

      /* lets hope at least the server hello and the start of the certificate block are in the first packet */
      cert_start = ntohs(get_u_int16_t(packet->payload, 7)) + 5 + 4;
      NDPI_LOG_DBG2(ndpi_struct, "suspected start of certificate: %u\n",
		    cert_start);

      if(cert_start < packet->payload_packet_len && packet->payload[cert_start] == 0x0b) {
	NDPI_LOG_DBG2(ndpi_struct,
		      "found 0x0b at suspected start of certificate block\n");
	return 2;
      }
    }

    if((packet->payload_packet_len > temp) && (packet->payload_packet_len > 100)) {
      /* the server hello may be split into small packets and the certificate has its own SSL Record
       * so temp contains only the length for the first ServerHello block */
      u_int32_t cert_start;

      NDPI_LOG_DBG2(ndpi_struct,
		    "maybe SSLv3 server hello split into smaller packets but with seperate record for the certificate\n");

      /* lets hope at least the server hello record and the start of the certificate record are in the first packet */
      cert_start = ntohs(get_u_int16_t(packet->payload, 7)) + 5 + 5 + 4;
      NDPI_LOG_DBG2(ndpi_struct, "suspected start of certificate: %u\n",
		    cert_start);

      if(cert_start < packet->payload_packet_len && packet->payload[cert_start] == 0x0b) {
	NDPI_LOG_DBG2(ndpi_struct,
		      "found 0x0b at suspected start of certificate block\n");
	return 2;
      }
    }


    if(packet->payload_packet_len >= temp + 5 && (packet->payload[temp] == 0x14 || packet->payload[temp] == 0x16)
       && packet->payload[temp + 1] == 0x03) {
      u_int32_t temp2 = ntohs(get_u_int16_t(packet->payload, temp + 3)) + 5;
      if(temp + temp2 > NDPI_MAX_SSL_REQUEST_SIZE) {
	return 1;
      }
      temp += temp2;
      NDPI_LOG_DBG2(ndpi_struct, "temp = %u\n", temp);
      if(packet->payload_packet_len == temp) {
	return 1;
      }
      if(packet->payload_packet_len >= temp + 5 &&
	 packet->payload[temp] == 0x16 && packet->payload[temp + 1] == 0x03) {
	temp2 = ntohs(get_u_int16_t(packet->payload, temp + 3)) + 5;
	if(temp + temp2 > NDPI_MAX_SSL_REQUEST_SIZE) {
	  return 1;
	}
	temp += temp2;
	NDPI_LOG_DBG2(ndpi_struct, "temp = %u\n", temp);
	if(packet->payload_packet_len == temp) {
	  return 1;
	}
	if(packet->payload_packet_len >= temp + 5 &&
	   packet->payload[temp] == 0x16 && packet->payload[temp + 1] == 0x03) {
	  temp2 = ntohs(get_u_int16_t(packet->payload, temp + 3)) + 5;
	  if(temp + temp2 > NDPI_MAX_SSL_REQUEST_SIZE) {
	    return 1;
	  }
	  temp += temp2;
	  NDPI_LOG_DBG2(ndpi_struct, "temp = %u\n", temp);
	  if(temp == packet->payload_packet_len) {
	    return 1;
	  }
	}
      }
    }
  }

  return 0;
}

void ndpi_search_ssl_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t ret;

  if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_SSL) {
    if(flow->l4.tcp.ssl_stage == 3 && packet->payload_packet_len > 20 && flow->packet_counter < 5) {
      /* this should only happen, when we detected SSL with a packet that had parts of the certificate in subsequent packets
       * so go on checking for certificate patterns for a couple more packets
       */
      NDPI_LOG_DBG2(ndpi_struct,
		    "ssl flow but check another packet for patterns\n");
      ssl_mark_and_payload_search_for_other_protocols(ndpi_struct, flow);
      if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_SSL) {
	/* still ssl so check another packet */
	return;
      } else {
	/* protocol has changed so we are done */
	return;
      }
    }
    return;
  }

  NDPI_LOG_DBG(ndpi_struct, "search ssl\n");

  /* Check if this is whatsapp first (this proto runs over port 443) */
  if((packet->payload_packet_len > 5)
     && ((packet->payload[0] == 'W')
	 && (packet->payload[1] == 'A')
	 && (packet->payload[4] == 0)
	 && (packet->payload[2] <= 9)
	 && (packet->payload[3] <= 9))) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WHATSAPP, NDPI_PROTOCOL_UNKNOWN);
    return;
  } else if((packet->payload_packet_len == 4)
	    && (packet->payload[0] == 'W')
	    && (packet->payload[1] == 'A')) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WHATSAPP, NDPI_PROTOCOL_UNKNOWN);
    return;
  } else {
    /* No whatsapp, let's try SSL */
    if(sslDetectProtocolFromCertificate(ndpi_struct, flow) > 0)
      return;
  }

  if(packet->payload_packet_len > 40 && flow->l4.tcp.ssl_stage == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "first ssl packet\n");
    // SSLv2 Record
    if(packet->payload[2] == 0x01 && packet->payload[3] == 0x03
       && (packet->payload[4] == 0x00 || packet->payload[4] == 0x01 || packet->payload[4] == 0x02)
       && (packet->payload_packet_len - packet->payload[1] == 2)) {
      NDPI_LOG_DBG2(ndpi_struct, "sslv2 len match\n");
      flow->l4.tcp.ssl_stage = 1 + packet->packet_direction;
      return;
    }

    if(packet->payload[0] == 0x16 && packet->payload[1] == 0x03
       && (packet->payload[2] == 0x00 || packet->payload[2] == 0x01 || packet->payload[2] == 0x02)
       && (packet->payload_packet_len - ntohs(get_u_int16_t(packet->payload, 3)) == 5)) {
      // SSLv3 Record
      NDPI_LOG_DBG2(ndpi_struct, "sslv3 len match\n");
      flow->l4.tcp.ssl_stage = 1 + packet->packet_direction;
      return;
    }

    // Application Data pkt
    if(packet->payload[0] == 0x17 && packet->payload[1] == 0x03
       && (packet->payload[2] == 0x00 || packet->payload[2] == 0x01 ||
           packet->payload[2] == 0x02 || packet->payload[2] == 0x03)) {
        if(packet->payload_packet_len - ntohs(get_u_int16_t(packet->payload, 3)) == 5) {
            NDPI_LOG_DBG2(ndpi_struct, "TLS len match\n");
            flow->l4.tcp.ssl_stage = 1 + packet->packet_direction;
            return;
        }
    }
  }

  if(packet->payload_packet_len > 40 &&
     flow->l4.tcp.ssl_stage == 1 + packet->packet_direction
     && flow->packet_direction_counter[packet->packet_direction] < 5) {
    return;
  }

  if(packet->payload_packet_len > 40 && flow->l4.tcp.ssl_stage == 2 - packet->packet_direction) {
    NDPI_LOG_DBG2(ndpi_struct, "second ssl packet\n");
    // SSLv2 Record
    if(packet->payload[2] == 0x01 && packet->payload[3] == 0x03
       && (packet->payload[4] == 0x00 || packet->payload[4] == 0x01 || packet->payload[4] == 0x02)
       && (packet->payload_packet_len - 2) >= packet->payload[1]) {
      NDPI_LOG_DBG2(ndpi_struct, "sslv2 server len match\n");
      ssl_mark_and_payload_search_for_other_protocols(ndpi_struct, flow);
      return;
    }

    ret = ndpi_search_sslv3_direction1(ndpi_struct, flow);
    if(ret == 1) {
      NDPI_LOG_DBG2(ndpi_struct, "sslv3 server len match\n");
      ssl_mark_and_payload_search_for_other_protocols(ndpi_struct, flow);
      return;
    } else if(ret == 2) {
      NDPI_LOG_DBG2(ndpi_struct,
		    "sslv3 server len match with split packet -> check some more packets for SSL patterns\n");
      ssl_mark_and_payload_search_for_other_protocols(ndpi_struct, flow);
      if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_SSL) {
	flow->l4.tcp.ssl_stage = 3;
      }
      return;
    }

    if(packet->payload_packet_len > 40 && flow->packet_direction_counter[packet->packet_direction] < 5) {
      NDPI_LOG_DBG2(ndpi_struct, "need next packet\n");
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  return;
}


void init_ssl_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("SSL", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SSL,
				      ndpi_search_ssl_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
