/*
 * ndpi_community_id.c
 *
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

#ifdef HAVE_CONFIG_H
#include "ndpi_config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include "ndpi_api.h"
#include "ndpi_config.h"

#include <time.h>
#ifndef WIN32
#include <unistd.h>
#endif

#if defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__
#include <sys/endian.h>
#endif

#include "ndpi_sha1.h"

#define NDPI_ICMP6_ECHO_REQUEST		128
#define NDPI_ICMP6_ECHO_REPLY		129
#define NDPI_MLD_LISTENER_QUERY		130
#define NDPI_MLD_LISTENER_REPORT	131

#define NDPI_ROUTER_SOLICIT		133
#define NDPI_ROUTER_ADVERT		134
#define NDPI_NEIGHBOR_SOLICIT		135
#define NDPI_NEIGHBOR_ADVERT		136

#define NDPI_ICMP_ECHOREPLY		0
#define	NDPI_ICMP_ECHO			8
#define	NDPI_ICMP_ROUTERADVERT		9
#define	NDPI_ICMP_ROUTERSOLICIT		10
#define	NDPI_ICMP_TIMESTAMP		13
#define	NDPI_ICMP_TIMESTAMPREPLY	14
#define	NDPI_ICMP_INFO_REQUEST		15
#define	NDPI_ICMP_INFO_REPLY		16
#define	NDPI_ICMP_MASKREQ		17
#define	NDPI_ICMP_MASKREPLY		18

#define NDPI_ICMP6_WRUREQUEST		139
#define NDPI_ICMP6_WRUREPLY		140

/* **************************************************** */

static ssize_t ndpi_community_id_buf_copy(u_int8_t * const dst, const void * const src, ssize_t len) {
  if(src)
    memcpy(dst, src, len);
  else
    memset(dst, 0, len);

  return len;
}

/* **************************************************** */

/*
  https://github.com/corelight/community-id-spec/blob/bda913f617389df07cdaa23606e11bbd318e265c/community-id.py#L56
*/
static u_int8_t ndpi_community_id_icmp_type_to_code_v4(u_int8_t icmp_type, u_int8_t icmp_code, int *is_one_way) {
  *is_one_way = 0;

  switch(icmp_type) {
  case NDPI_ICMP_ECHO:
    return NDPI_ICMP_ECHOREPLY;
  case NDPI_ICMP_ECHOREPLY:
    return NDPI_ICMP_ECHO;
  case NDPI_ICMP_TIMESTAMP:
    return NDPI_ICMP_TIMESTAMPREPLY;
  case NDPI_ICMP_TIMESTAMPREPLY:
    return NDPI_ICMP_TIMESTAMP;
  case NDPI_ICMP_INFO_REQUEST:
    return NDPI_ICMP_INFO_REPLY;
  case NDPI_ICMP_INFO_REPLY:
    return NDPI_ICMP_INFO_REQUEST;
  case NDPI_ICMP_ROUTERSOLICIT:
    return NDPI_ICMP_ROUTERADVERT;
  case NDPI_ICMP_ROUTERADVERT:
    return NDPI_ICMP_ROUTERSOLICIT;
  case NDPI_ICMP_MASKREQ:
    return NDPI_ICMP_MASKREPLY;
  case NDPI_ICMP_MASKREPLY:
    return NDPI_ICMP_MASKREQ;
  default:
    *is_one_way = 1;
    return icmp_code;
  }
}

/* **************************************************** */

/*
  https://github.com/corelight/community-id-spec/blob/bda913f617389df07cdaa23606e11bbd318e265c/community-id.py#L83
*/
static u_int8_t ndpi_community_id_icmp_type_to_code_v6(u_int8_t icmp_type, u_int8_t icmp_code, int *is_one_way) {
  *is_one_way = 0;

  switch(icmp_type) {
  case NDPI_ICMP6_ECHO_REQUEST:
    return NDPI_ICMP6_ECHO_REPLY;
  case NDPI_ICMP6_ECHO_REPLY:
    return NDPI_ICMP6_ECHO_REQUEST;
  case NDPI_ROUTER_SOLICIT:
    return NDPI_ROUTER_ADVERT;
  case NDPI_ROUTER_ADVERT:
    return NDPI_ROUTER_SOLICIT;
  case NDPI_NEIGHBOR_SOLICIT:
    return NDPI_NEIGHBOR_ADVERT;
  case NDPI_NEIGHBOR_ADVERT:
    return NDPI_NEIGHBOR_SOLICIT;
  case NDPI_MLD_LISTENER_QUERY:
    return NDPI_MLD_LISTENER_REPORT;
  case NDPI_MLD_LISTENER_REPORT:
    return NDPI_MLD_LISTENER_QUERY;
  case NDPI_ICMP6_WRUREQUEST:
    return NDPI_ICMP6_WRUREPLY;
  case NDPI_ICMP6_WRUREPLY:
    return NDPI_ICMP6_WRUREQUEST;
  // Home Agent Address Discovery Request Message and reply
  case 144:
    return 145;
  case 145:
    return 144;
  default:
    *is_one_way = 1;
    return icmp_code;
  }
}

/* **************************************************** */

/* 
  https://github.com/corelight/community-id-spec/blob/bda913f617389df07cdaa23606e11bbd318e265c/community-id.py#L164
*/
static int ndpi_community_id_peer_v4_is_less_than(u_int32_t ip1, u_int32_t ip2, u_int16_t p1, u_int16_t p2) {
  int comp = memcmp(&ip1, &ip2, sizeof(u_int32_t));
  return comp < 0 || (comp == 0 && p1 < p2);
}

/* **************************************************** */

static int ndpi_community_id_peer_v6_is_less_than(struct ndpi_in6_addr *ip1, struct ndpi_in6_addr *ip2, u_int16_t p1, u_int16_t p2) {
  int comp = memcmp(ip1, ip2, sizeof(struct ndpi_in6_addr));
  return comp < 0 || (comp == 0 && p1 < p2);
}

/* **************************************************** */

static void ndpi_community_id_sha1_hash(const uint8_t *message, size_t len, u_char *hash /* 20-bytes */) {
  SHA1_CTX ctx;
  SHA1Init(&ctx);
  SHA1Update(&ctx, message, len);
  SHA1Final(hash, &ctx);
}

/* **************************************************** */

/*
https://github.com/corelight/community-id-spec/blob/bda913f617389df07cdaa23606e11bbd318e265c/community-id.py#L285
*/
static int ndpi_community_id_finalize_and_compute_hash(u_int8_t *comm_buf, u_int16_t off, u_int8_t l4_proto,
             u_int16_t src_port, u_int16_t dst_port, char *hash_buf, u_int8_t hash_buf_len) {
  u_int8_t pad = 0;
  uint32_t hash[5];
  char *community_id;

  /* L4 proto */
  off += ndpi_community_id_buf_copy(&comm_buf[off], &l4_proto, sizeof(l4_proto));

  /* Pad */
  off += ndpi_community_id_buf_copy(&comm_buf[off], &pad, sizeof(pad));

  /* Source and destination ports */
  switch(l4_proto) {
  case IPPROTO_ICMP:
  case IPPROTO_ICMPV6:
  case IPPROTO_SCTP:
  case IPPROTO_UDP:
  case IPPROTO_TCP:
    off += ndpi_community_id_buf_copy(&comm_buf[off], &src_port, sizeof(src_port));
    off += ndpi_community_id_buf_copy(&comm_buf[off], &dst_port, sizeof(dst_port));
    break;
  }

  /* Compute SHA1 */
  ndpi_community_id_sha1_hash(comm_buf, off, (u_char*)hash);

  /* Base64 encoding */
  community_id = ndpi_base64_encode((u_int8_t*)hash, sizeof(hash));

  if (community_id == NULL)
    return -1;

#if 0 /* Debug Info */
  printf("Hex output: ");
  for(int i = 0; i < off; i++)
    printf("%.2x ", comm_buf[i]);
  printf("\n");

  printf("Sha1 sum: ");
  for(int i = 0; i < 5; i++)
    printf("%.2x ", ntohl(hash[i]));
  printf("\n");

  printf("Base64: %s\n", community_id);
#endif

  if (hash_buf_len < 2 || hash_buf_len-2 < strlen(community_id)+1) {
    ndpi_free(community_id);
    return -1;
  }

  /* Writing hash */
  hash_buf[0] = '1';
  hash_buf[1] = ':';
  strcpy(&hash_buf[2], community_id);
  ndpi_free(community_id);

  return 0;
}

/* **************************************************** */

/*
  NOTE:
  - Leave fields empty/zero when information is missing (e.g. with ICMP ports are zero)
  - The hash_buf most be 30+1 bits or longer
  - Return code: 0 = OK, -1 otherwise
*/

int ndpi_flowv4_flow_hash(u_int8_t l4_proto, u_int32_t src_ip, u_int32_t dst_ip,
                          u_int16_t src_port, u_int16_t dst_port,
                          u_int8_t icmp_type, u_int8_t icmp_code,
                          u_char *hash_buf, u_int8_t hash_buf_len) {
  /*
    Input buffer (40 bytes)
     2 - Seed 
    16 - IPv6 src 
    16 - IPv6 dst
     1 - L4 proto
     1 - Pad 
     2 - Port src
     2 - Port dst
  */
  u_int8_t comm_buf[40] = { 0 };
  u_int16_t off = 0;
  u_int16_t seed = 0;
  u_int32_t *ip_a_ptr, *ip_b_ptr;
  u_int16_t port_a, port_b;
  int icmp_one_way = 0;

  /* Adjust the ports according to the specs */
  switch(l4_proto) {
  case IPPROTO_ICMP:
    src_port = icmp_type;
    dst_port = ndpi_community_id_icmp_type_to_code_v4(icmp_type, icmp_code, &icmp_one_way);
    break;
  case IPPROTO_SCTP:
  case IPPROTO_UDP:
  case IPPROTO_TCP:
    /* src/dst port ok */
    break;
  default:
    src_port = dst_port = 0;
    break;
  }

  /* Convert tuple to NBO */
  src_ip = htonl(src_ip);
  dst_ip = htonl(dst_ip);
  src_port = htons(src_port);
  dst_port = htons(dst_port);

  /*
    The community id hash doesn't have the definition of client and server, it just sorts IP addresses
    and ports to make sure the smaller ip address is the first. This performs this check and
    possibly swap client ip and port.
  */
  if(icmp_one_way || ndpi_community_id_peer_v4_is_less_than(src_ip, dst_ip, src_port, dst_port)) {
    ip_a_ptr = &src_ip, ip_b_ptr = &dst_ip;
    port_a = src_port, port_b = dst_port;
  } else {
    /* swap flow peers */
    ip_a_ptr = &dst_ip, ip_b_ptr = &src_ip;
    port_a = dst_port, port_b = src_port;
  }

  /* Seed */
  off = ndpi_community_id_buf_copy(&comm_buf[off], &seed, sizeof(seed));

  /* Source and destination IPs */
  off += ndpi_community_id_buf_copy(&comm_buf[off], ip_a_ptr, sizeof(src_ip));
  off += ndpi_community_id_buf_copy(&comm_buf[off], ip_b_ptr, sizeof(dst_ip));

  return ndpi_community_id_finalize_and_compute_hash(comm_buf, off,
           l4_proto, port_a, port_b, (char*)hash_buf, hash_buf_len);
}

/* **************************************************** */

int ndpi_flowv6_flow_hash(u_int8_t l4_proto, struct ndpi_in6_addr *src_ip, struct ndpi_in6_addr *dst_ip,
                          u_int16_t src_port, u_int16_t dst_port,
                          u_int8_t icmp_type, u_int8_t icmp_code,
                          u_char *hash_buf, u_int8_t hash_buf_len) {
  u_int8_t comm_buf[40] = { 0 };
  u_int16_t off = 0;
  u_int16_t seed = 0;
  struct ndpi_in6_addr *ip_a_ptr, *ip_b_ptr;
  u_int16_t port_a, port_b;
  int icmp_one_way = 0;

  switch(l4_proto) {
  case IPPROTO_ICMPV6:
    src_port = icmp_type;
    dst_port = ndpi_community_id_icmp_type_to_code_v6(icmp_type, icmp_code, &icmp_one_way);
    break;
  case IPPROTO_SCTP:
  case IPPROTO_UDP:
  case IPPROTO_TCP:
    /* src/dst port ok */
    break;
  default:
    src_port = dst_port = 0;
    break;
  }

  /* Convert tuple to NBO */
  src_port = htons(src_port);
  dst_port = htons(dst_port);

  if(icmp_one_way || ndpi_community_id_peer_v6_is_less_than(src_ip, dst_ip, src_port, dst_port)) {
    ip_a_ptr = src_ip, ip_b_ptr = dst_ip;
    port_a = src_port, port_b = dst_port;
  } else {
    ip_a_ptr = dst_ip, ip_b_ptr = src_ip;
    port_a = dst_port, port_b = src_port;
  }

  /* Seed */
  off = ndpi_community_id_buf_copy(&comm_buf[off], &seed, sizeof(seed));

  /* Source and destination IPs */
  off += ndpi_community_id_buf_copy(&comm_buf[off], ip_a_ptr, sizeof(struct ndpi_in6_addr));
  off += ndpi_community_id_buf_copy(&comm_buf[off], ip_b_ptr, sizeof(struct ndpi_in6_addr));

  return ndpi_community_id_finalize_and_compute_hash(comm_buf, off,
           l4_proto, port_a, port_b, (char*)hash_buf, hash_buf_len);
}

/* **************************************************** */
