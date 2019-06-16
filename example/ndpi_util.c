/*
 * ndpi_util.c
 *
 * Copyright (C) 2011-18 - ntop.org
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

#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#endif

#ifndef ETH_P_IP
#define ETH_P_IP               0x0800 	/* IPv4 */
#endif

#ifndef ETH_P_IPv6
#define ETH_P_IPV6	       0x86dd	/* IPv6 */
#endif

#define SLARP                  0x8035   /* Cisco Slarp */
#define CISCO_D_PROTO          0x2000	/* Cisco Discovery Protocol */

#define VLAN                   0x8100
#define MPLS_UNI               0x8847
#define MPLS_MULTI             0x8848
#define PPPoE                  0x8864
#define SNAP                   0xaa
#define BSTP                   0x42     /* Bridge Spanning Tree Protocol */

/* mask for FCF */
#define	WIFI_DATA                        0x2    /* 0000 0010 */
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    /* 0000 0011 = 0x3 */
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    /* 0000 1111 = 0xF */
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)

/* mask for Bad FCF presence */
#define BAD_FCS                         0x50    /* 0101 0000 */

#define GTP_U_V1_PORT                   2152
#define TZSP_PORT                      37008

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL  113
#endif

#include "ndpi_main.h"
#include "ndpi_util.h"

extern u_int8_t enable_protocol_guess;

/* ***************************************************** */

void ndpi_free_flow_info_half(struct ndpi_flow_info *flow) {
  if(flow->ndpi_flow) { ndpi_flow_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
  if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL; }
  if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL; }
}

/* ***************************************************** */

extern u_int32_t current_ndpi_memory, max_ndpi_memory;

/**
 * @brief malloc wrapper function
 */
static void *malloc_wrapper(size_t size) {
  current_ndpi_memory += size;

  if(current_ndpi_memory > max_ndpi_memory)
    max_ndpi_memory = current_ndpi_memory;

  return malloc(size);
}

/* ***************************************************** */

const char* print_cipher_id(u_int32_t cipher) {
  switch(cipher) {
  case 0x000000: return("TLS_NULL_WITH_NULL_NULL");
  case 0x000001: return("TLS_RSA_WITH_NULL_MD5");
  case 0x000002: return("TLS_RSA_WITH_NULL_SHA");
  case 0x000003: return("TLS_RSA_EXPORT_WITH_RC4_40_MD5");
  case 0x000004: return("TLS_RSA_WITH_RC4_128_MD5");
  case 0x000005: return("TLS_RSA_WITH_RC4_128_SHA");
  case 0x000006: return("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5");
  case 0x000007: return("TLS_RSA_WITH_IDEA_CBC_SHA");
  case 0x000008: return("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA");
  case 0x000009: return("TLS_RSA_WITH_DES_CBC_SHA");
  case 0x00000a: return("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00000b: return("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA");
  case 0x00000c: return("TLS_DH_DSS_WITH_DES_CBC_SHA");
  case 0x00000d: return("TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA");
  case 0x00000e: return("TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA");
  case 0x00000f: return("TLS_DH_RSA_WITH_DES_CBC_SHA");
  case 0x000010: return("TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x000011: return("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA");
  case 0x000012: return("TLS_DHE_DSS_WITH_DES_CBC_SHA");
  case 0x000013: return("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA");
  case 0x000014: return("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA");
  case 0x000015: return("TLS_DHE_RSA_WITH_DES_CBC_SHA");
  case 0x000016: return("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x000017: return("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5");
  case 0x000018: return("TLS_DH_anon_WITH_RC4_128_MD5");
  case 0x000019: return("TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA");
  case 0x00001a: return("TLS_DH_anon_WITH_DES_CBC_SHA");
  case 0x00001b: return("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA");
  case 0x00001c: return("SSL_FORTEZZA_KEA_WITH_NULL_SHA");
  case 0x00001d: return("SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA");
    /* case 0x00001e: return("SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"); */
  case 0x00001E: return("TLS_KRB5_WITH_DES_CBC_SHA");
  case 0x00001F: return("TLS_KRB5_WITH_3DES_EDE_CBC_SHA");
  case 0x000020: return("TLS_KRB5_WITH_RC4_128_SHA");
  case 0x000021: return("TLS_KRB5_WITH_IDEA_CBC_SHA");
  case 0x000022: return("TLS_KRB5_WITH_DES_CBC_MD5");
  case 0x000023: return("TLS_KRB5_WITH_3DES_EDE_CBC_MD5");
  case 0x000024: return("TLS_KRB5_WITH_RC4_128_MD5");
  case 0x000025: return("TLS_KRB5_WITH_IDEA_CBC_MD5");
  case 0x000026: return("TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA");
  case 0x000027: return("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA");
  case 0x000028: return("TLS_KRB5_EXPORT_WITH_RC4_40_SHA");
  case 0x000029: return("TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5");
  case 0x00002A: return("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5");
  case 0x00002B: return("TLS_KRB5_EXPORT_WITH_RC4_40_MD5");
  case 0x00002C: return("TLS_PSK_WITH_NULL_SHA");
  case 0x00002D: return("TLS_DHE_PSK_WITH_NULL_SHA");
  case 0x00002E: return("TLS_RSA_PSK_WITH_NULL_SHA");
  case 0x00002f: return("TLS_RSA_WITH_AES_128_CBC_SHA");
  case 0x000030: return("TLS_DH_DSS_WITH_AES_128_CBC_SHA");
  case 0x000031: return("TLS_DH_RSA_WITH_AES_128_CBC_SHA");
  case 0x000032: return("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
  case 0x000033: return("TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
  case 0x000034: return("TLS_DH_anon_WITH_AES_128_CBC_SHA");
  case 0x000035: return("TLS_RSA_WITH_AES_256_CBC_SHA");
  case 0x000036: return("TLS_DH_DSS_WITH_AES_256_CBC_SHA");
  case 0x000037: return("TLS_DH_RSA_WITH_AES_256_CBC_SHA");
  case 0x000038: return("TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
  case 0x000039: return("TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
  case 0x00003A: return("TLS_DH_anon_WITH_AES_256_CBC_SHA");
  case 0x00003B: return("TLS_RSA_WITH_NULL_SHA256");
  case 0x00003C: return("TLS_RSA_WITH_AES_128_CBC_SHA256");
  case 0x00003D: return("TLS_RSA_WITH_AES_256_CBC_SHA256");
  case 0x00003E: return("TLS_DH_DSS_WITH_AES_128_CBC_SHA256");
  case 0x00003F: return("TLS_DH_RSA_WITH_AES_128_CBC_SHA256");
  case 0x000040: return("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
  case 0x000041: return("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000042: return("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000043: return("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000044: return("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000045: return("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000046: return("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000047: return("TLS_ECDH_ECDSA_WITH_NULL_SHA");
  case 0x000048: return("TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
  case 0x000049: return("TLS_ECDH_ECDSA_WITH_DES_CBC_SHA");
  case 0x00004A: return("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00004B: return("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
  case 0x00004C: return("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
  case 0x000060: return("TLS_RSA_EXPORT1024_WITH_RC4_56_MD5");
  case 0x000061: return("TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5");
  case 0x000062: return("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA");
  case 0x000063: return("TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA");
  case 0x000064: return("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA");
  case 0x000065: return("TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA");
  case 0x000066: return("TLS_DHE_DSS_WITH_RC4_128_SHA");
  case 0x000067: return("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
  case 0x000068: return("TLS_DH_DSS_WITH_AES_256_CBC_SHA256");
  case 0x000069: return("TLS_DH_RSA_WITH_AES_256_CBC_SHA256");
  case 0x00006A: return("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");
  case 0x00006B: return("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
  case 0x00006C: return("TLS_DH_anon_WITH_AES_128_CBC_SHA256");
  case 0x00006D: return("TLS_DH_anon_WITH_AES_256_CBC_SHA256");
  case 0x000084: return("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA");
  case 0x000085: return("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA");
  case 0x000086: return("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA");
  case 0x000087: return("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA");
  case 0x000088: return("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA");
  case 0x000089: return("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA");
  case 0x00008A: return("TLS_PSK_WITH_RC4_128_SHA");
  case 0x00008B: return("TLS_PSK_WITH_3DES_EDE_CBC_SHA");
  case 0x00008C: return("TLS_PSK_WITH_AES_128_CBC_SHA");
  case 0x00008D: return("TLS_PSK_WITH_AES_256_CBC_SHA");
  case 0x00008E: return("TLS_DHE_PSK_WITH_RC4_128_SHA");
  case 0x00008F: return("TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA");
  case 0x000090: return("TLS_DHE_PSK_WITH_AES_128_CBC_SHA");
  case 0x000091: return("TLS_DHE_PSK_WITH_AES_256_CBC_SHA");
  case 0x000092: return("TLS_RSA_PSK_WITH_RC4_128_SHA");
  case 0x000093: return("TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA");
  case 0x000094: return("TLS_RSA_PSK_WITH_AES_128_CBC_SHA");
  case 0x000095: return("TLS_RSA_PSK_WITH_AES_256_CBC_SHA");
  case 0x000096: return("TLS_RSA_WITH_SEED_CBC_SHA");
  case 0x000097: return("TLS_DH_DSS_WITH_SEED_CBC_SHA");
  case 0x000098: return("TLS_DH_RSA_WITH_SEED_CBC_SHA");
  case 0x000099: return("TLS_DHE_DSS_WITH_SEED_CBC_SHA");
  case 0x00009A: return("TLS_DHE_RSA_WITH_SEED_CBC_SHA");
  case 0x00009B: return("TLS_DH_anon_WITH_SEED_CBC_SHA");
  case 0x00009C: return("TLS_RSA_WITH_AES_128_GCM_SHA256");
  case 0x00009D: return("TLS_RSA_WITH_AES_256_GCM_SHA384");
  case 0x00009E: return("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
  case 0x00009F: return("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
  case 0x0000A0: return("TLS_DH_RSA_WITH_AES_128_GCM_SHA256");
  case 0x0000A1: return("TLS_DH_RSA_WITH_AES_256_GCM_SHA384");
  case 0x0000A2: return("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
  case 0x0000A3: return("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
  case 0x0000A4: return("TLS_DH_DSS_WITH_AES_128_GCM_SHA256");
  case 0x0000A5: return("TLS_DH_DSS_WITH_AES_256_GCM_SHA384");
  case 0x0000A6: return("TLS_DH_anon_WITH_AES_128_GCM_SHA256");
  case 0x0000A7: return("TLS_DH_anon_WITH_AES_256_GCM_SHA384");
  case 0x0000A8: return("TLS_PSK_WITH_AES_128_GCM_SHA256");
  case 0x0000A9: return("TLS_PSK_WITH_AES_256_GCM_SHA384");
  case 0x0000AA: return("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256");
  case 0x0000AB: return("TLS_DHE_PSK_WITH_AES_256_GCM_SHA384");
  case 0x0000AC: return("TLS_RSA_PSK_WITH_AES_128_GCM_SHA256");
  case 0x0000AD: return("TLS_RSA_PSK_WITH_AES_256_GCM_SHA384");
  case 0x0000AE: return("TLS_PSK_WITH_AES_128_CBC_SHA256");
  case 0x0000AF: return("TLS_PSK_WITH_AES_256_CBC_SHA384");
  case 0x0000B0: return("TLS_PSK_WITH_NULL_SHA256");
  case 0x0000B1: return("TLS_PSK_WITH_NULL_SHA384");
  case 0x0000B2: return("TLS_DHE_PSK_WITH_AES_128_CBC_SHA256");
  case 0x0000B3: return("TLS_DHE_PSK_WITH_AES_256_CBC_SHA384");
  case 0x0000B4: return("TLS_DHE_PSK_WITH_NULL_SHA256");
  case 0x0000B5: return("TLS_DHE_PSK_WITH_NULL_SHA384");
  case 0x0000B6: return("TLS_RSA_PSK_WITH_AES_128_CBC_SHA256");
  case 0x0000B7: return("TLS_RSA_PSK_WITH_AES_256_CBC_SHA384");
  case 0x0000B8: return("TLS_RSA_PSK_WITH_NULL_SHA256");
  case 0x0000B9: return("TLS_RSA_PSK_WITH_NULL_SHA384");
  case 0x0000BA: return("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000BB: return("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000BC: return("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000BD: return("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000BE: return("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000BF: return("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000C0: return("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000C1: return("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000C2: return("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000C3: return("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000C4: return("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000C5: return("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000FF: return("TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
  case 0x00c001: return("TLS_ECDH_ECDSA_WITH_NULL_SHA");
  case 0x00c002: return("TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
  case 0x00c003: return("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00c004: return("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
  case 0x00c005: return("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
  case 0x00c006: return("TLS_ECDHE_ECDSA_WITH_NULL_SHA");
  case 0x00c007: return("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
  case 0x00c008: return("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00c009: return("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
  case 0x00c00a: return("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
  case 0x00c00b: return("TLS_ECDH_RSA_WITH_NULL_SHA");
  case 0x00c00c: return("TLS_ECDH_RSA_WITH_RC4_128_SHA");
  case 0x00c00d: return("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00c00e: return("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA");
  case 0x00c00f: return("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA");
  case 0x00c010: return("TLS_ECDHE_RSA_WITH_NULL_SHA");
  case 0x00c011: return("TLS_ECDHE_RSA_WITH_RC4_128_SHA");
  case 0x00c012: return("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00c013: return("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
  case 0x00c014: return("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
  case 0x00c015: return("TLS_ECDH_anon_WITH_NULL_SHA");
  case 0x00c016: return("TLS_ECDH_anon_WITH_RC4_128_SHA");
  case 0x00c017: return("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA");
  case 0x00c018: return("TLS_ECDH_anon_WITH_AES_128_CBC_SHA");
  case 0x00c019: return("TLS_ECDH_anon_WITH_AES_256_CBC_SHA");
  case 0x00C01A: return("TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA");
  case 0x00C01B: return("TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00C01C: return("TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA");
  case 0x00C01D: return("TLS_SRP_SHA_WITH_AES_128_CBC_SHA");
  case 0x00C01E: return("TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA");
  case 0x00C01F: return("TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA");
  case 0x00C020: return("TLS_SRP_SHA_WITH_AES_256_CBC_SHA");
  case 0x00C021: return("TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA");
  case 0x00C022: return("TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA");
  case 0x00C023: return("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
  case 0x00C024: return("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
  case 0x00C025: return("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256");
  case 0x00C026: return("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384");
  case 0x00C027: return("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
  case 0x00C028: return("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
  case 0x00C029: return("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256");
  case 0x00C02A: return("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384");
  case 0x00C02B: return("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
  case 0x00C02C: return("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
  case 0x00C02D: return("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
  case 0x00C02E: return("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384");
  case 0x00C02F: return("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
  case 0x00C030: return("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
  case 0x00C031: return("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256");
  case 0x00C032: return("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384");
  case 0x00C033: return("TLS_ECDHE_PSK_WITH_RC4_128_SHA");
  case 0x00C034: return("TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA");
  case 0x00C035: return("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA");
  case 0x00C036: return("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA");
  case 0x00C037: return("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256");
  case 0x00C038: return("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384");
  case 0x00C039: return("TLS_ECDHE_PSK_WITH_NULL_SHA");
  case 0x00C03A: return("TLS_ECDHE_PSK_WITH_NULL_SHA256");
  case 0x00C03B: return("TLS_ECDHE_PSK_WITH_NULL_SHA384");
  case 0x00CC13: return("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CC14: return("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CC15: return("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCA8: return("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCA9: return("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCAA: return("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCAB: return("TLS_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCAC: return("TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCAD: return("TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCAE: return("TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00E410: return("TLS_RSA_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E411: return("TLS_RSA_WITH_SALSA20_SHA1");
  case 0x00E412: return("TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E413: return("TLS_ECDHE_RSA_WITH_SALSA20_SHA1");
  case 0x00E414: return("TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E415: return("TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1");
  case 0x00E416: return("TLS_PSK_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E417: return("TLS_PSK_WITH_SALSA20_SHA1");
  case 0x00E418: return("TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E419: return("TLS_ECDHE_PSK_WITH_SALSA20_SHA1");
  case 0x00E41A: return("TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E41B: return("TLS_RSA_PSK_WITH_SALSA20_SHA1");
  case 0x00E41C: return("TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E41D: return("TLS_DHE_PSK_WITH_SALSA20_SHA1");
  case 0x00E41E: return("TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E41F: return("TLS_DHE_RSA_WITH_SALSA20_SHA1");
  case 0x00fefe: return("SSL_RSA_FIPS_WITH_DES_CBC_SHA");
  case 0x00feff: return("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA");
  case 0x00ffe0: return("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA");
  case 0x00ffe1: return("SSL_RSA_FIPS_WITH_DES_CBC_SHA");
  case 0x010080: return("SSL2_RC4_128_WITH_MD5");
  case 0x020080: return("SSL2_RC4_128_EXPORT40_WITH_MD5");
  case 0x030080: return("SSL2_RC2_128_CBC_WITH_MD5");
  case 0x040080: return("SSL2_RC2_128_CBC_EXPORT40_WITH_MD5");
  case 0x050080: return("SSL2_IDEA_128_CBC_WITH_MD5");
  case 0x060040: return("SSL2_DES_64_CBC_WITH_MD5");
  case 0x0700c0: return("SSL2_DES_192_EDE3_CBC_WITH_MD5");
  case 0x080080: return("SSL2_RC4_64_WITH_MD5");
  default: return("???");
  }
}

/* ***************************************************** */

/**
 * @brief free wrapper function
 */
static void free_wrapper(void *freeable) {
  free(freeable);
}

/* ***************************************************** */

static uint16_t ndpi_get_proto_id(struct ndpi_detection_module_struct *ndpi_mod, const char *name) {
  uint16_t proto_id;
  char *e;
  unsigned long p = strtol(name,&e,0);
  ndpi_proto_defaults_t *proto_defaults = ndpi_get_proto_defaults(ndpi_mod);

  if(e && !*e) {
    if(p < NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS &&
       proto_defaults[p].protoName) return (uint16_t)p;
    return NDPI_PROTOCOL_UNKNOWN;
  }

  for(proto_id=NDPI_PROTOCOL_UNKNOWN; proto_id < NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS; proto_id++) {
    if(proto_defaults[proto_id].protoName &&
       !strcasecmp(proto_defaults[proto_id].protoName,name))
      return proto_id;
  }
  return NDPI_PROTOCOL_UNKNOWN;
}

/* ***************************************************** */

static NDPI_PROTOCOL_BITMASK debug_bitmask;
static char _proto_delim[] = " \t,:;";
static int parse_debug_proto(struct ndpi_detection_module_struct *ndpi_mod, char *str) {
  char *n;
  uint16_t proto;
  char op=1;
  for(n = strtok(str,_proto_delim); n && *n; n = strtok(NULL,_proto_delim)) {
    if(*n == '-') {
      op = 0;
      n++;
    } else if(*n == '+') {
      op = 1;
      n++;
    }
    if(!strcmp(n,"all")) {
      if(op)
	NDPI_BITMASK_SET_ALL(debug_bitmask);
      else
	NDPI_BITMASK_RESET(debug_bitmask);
      continue;
    }
    proto = ndpi_get_proto_id(ndpi_mod, n);
    if(proto == NDPI_PROTOCOL_UNKNOWN && strcmp(n,"unknown") && strcmp(n,"0")) {
      fprintf(stderr,"Invalid protocol %s\n",n);
      return 1;
    }
    if(op)
      NDPI_BITMASK_ADD(debug_bitmask,proto);
    else
      NDPI_BITMASK_DEL(debug_bitmask,proto);
  }
  return 0;
}

/* ***************************************************** */

extern char *_debug_protocols;
static int _debug_protocols_ok = 0;

struct ndpi_workflow* ndpi_workflow_init(const struct ndpi_workflow_prefs * prefs,
					 pcap_t * pcap_handle) {
  set_ndpi_malloc(malloc_wrapper), set_ndpi_free(free_wrapper);
  set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);
  /* TODO: just needed here to init ndpi malloc wrapper */
  struct ndpi_detection_module_struct * module = ndpi_init_detection_module();

  struct ndpi_workflow * workflow = ndpi_calloc(1, sizeof(struct ndpi_workflow));

  workflow->pcap_handle = pcap_handle;
  workflow->prefs       = *prefs;
  workflow->ndpi_struct = module;

  if(workflow->ndpi_struct == NULL) {
    NDPI_LOG(0, NULL, NDPI_LOG_ERROR, "global structure initialization failed\n");
    exit(-1);
  }

  ndpi_set_log_level(module, nDPI_LogLevel);

  if(_debug_protocols != NULL && ! _debug_protocols_ok) {
    if(parse_debug_proto(module,_debug_protocols))
      exit(-1);
    _debug_protocols_ok = 1;
  }

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  NDPI_BITMASK_RESET(module->debug_bitmask);
  if(_debug_protocols_ok)
    module->debug_bitmask = debug_bitmask;
#endif

  workflow->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));

  return workflow;
}

/* ***************************************************** */

void ndpi_flow_info_freer(void *node) {
  struct ndpi_flow_info *flow = (struct ndpi_flow_info*)node;

  ndpi_free_flow_info_half(flow);
  ndpi_free(flow);
}

/* ***************************************************** */

void ndpi_workflow_free(struct ndpi_workflow * workflow) {
  u_int i;

  for(i=0; i<workflow->prefs.num_roots; i++)
    ndpi_tdestroy(workflow->ndpi_flows_root[i], ndpi_flow_info_freer);

  ndpi_exit_detection_module(workflow->ndpi_struct);
  free(workflow->ndpi_flows_root);
  free(workflow);
}

/* ***************************************************** */

int ndpi_workflow_node_cmp(const void *a, const void *b) {
  const struct ndpi_flow_info *fa = (const struct ndpi_flow_info*)a;
  const struct ndpi_flow_info *fb = (const struct ndpi_flow_info*)b;

  if(fa->hashval < fb->hashval) return(-1); else if(fa->hashval > fb->hashval) return(1);

  /* Flows have the same hash */

  if(fa->vlan_id   < fb->vlan_id   ) return(-1); else { if(fa->vlan_id    > fb->vlan_id   ) return(1); }
  if(fa->protocol  < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  if(
    (
      (fa->src_ip      == fb->src_ip  )
      && (fa->src_port == fb->src_port)
      && (fa->dst_ip   == fb->dst_ip  )
      && (fa->dst_port == fb->dst_port)
      )
    ||
    (
      (fa->src_ip      == fb->dst_ip  )
      && (fa->src_port == fb->dst_port)
      && (fa->dst_ip   == fb->src_ip  )
      && (fa->dst_port == fb->src_port)
      )
    )
    return(0);

  if(fa->src_ip   < fb->src_ip  ) return(-1); else { if(fa->src_ip   > fb->src_ip  ) return(1); }
  if(fa->src_port < fb->src_port) return(-1); else { if(fa->src_port > fb->src_port) return(1); }
  if(fa->dst_ip   < fb->dst_ip  ) return(-1); else { if(fa->dst_ip   > fb->dst_ip  ) return(1); }
  if(fa->dst_port < fb->dst_port) return(-1); else { if(fa->dst_port > fb->dst_port) return(1); }

  return(0); /* notreached */
}

/* ***************************************************** */

static void patchIPv6Address(char *str) {
  int i = 0, j = 0;

  while(str[i] != '\0') {
    if((str[i] == ':')
       && (str[i+1] == '0')
       && (str[i+2] == ':')) {
      str[j++] = ':';
      str[j++] = ':';
      i += 3;
    } else
      str[j++] = str[i++];
  }
  if(str[j] != '\0') str[j] = '\0';
}

/* ***************************************************** */

static struct ndpi_flow_info *get_ndpi_flow_info(struct ndpi_workflow * workflow,
						 const u_int8_t version,
						 u_int16_t vlan_id,
						 const struct ndpi_iphdr *iph,
						 const struct ndpi_ipv6hdr *iph6,
						 u_int16_t ip_offset,
						 u_int16_t ipsize,
						 u_int16_t l4_packet_len,
						 struct ndpi_tcphdr **tcph,
						 struct ndpi_udphdr **udph,
						 u_int16_t *sport, u_int16_t *dport,
						 struct ndpi_id_struct **src,
						 struct ndpi_id_struct **dst,
						 u_int8_t *proto,
						 u_int8_t **payload,
						 u_int16_t *payload_len,
						 u_int8_t *src_to_dst_direction) {
  u_int32_t idx, l4_offset, hashval;
  struct ndpi_flow_info flow;
  void *ret;
  const u_int8_t *l3, *l4;

  /*
    Note: to keep things simple (ndpiReader is just a demo app)
    we handle IPv6 a-la-IPv4.
  */
  if(version == IPVERSION) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       /* || (iph->frag_off & htons(0x1FFF)) != 0 */)
      return NULL;

    l4_offset = iph->ihl * 4;
    l3 = (const u_int8_t*)iph;
  } else {
    l4_offset = sizeof(struct ndpi_ipv6hdr);
    l3 = (const u_int8_t*)iph6;
  }

  if(l4_packet_len < 64)
    workflow->stats.packet_len[0]++;
  else if(l4_packet_len >= 64 && l4_packet_len < 128)
    workflow->stats.packet_len[1]++;
  else if(l4_packet_len >= 128 && l4_packet_len < 256)
    workflow->stats.packet_len[2]++;
  else if(l4_packet_len >= 256 && l4_packet_len < 1024)
    workflow->stats.packet_len[3]++;
  else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
    workflow->stats.packet_len[4]++;
  else if(l4_packet_len >= 1500)
    workflow->stats.packet_len[5]++;

  if(l4_packet_len > workflow->stats.max_packet_len)
    workflow->stats.max_packet_len = l4_packet_len;

  *proto = iph->protocol;
  l4 = ((const u_int8_t *) l3 + l4_offset);

  if(iph->protocol == IPPROTO_TCP && l4_packet_len >= 20) {
    u_int tcp_len;

    // tcp
    workflow->stats.tcp_count++;
    *tcph = (struct ndpi_tcphdr *)l4;
    *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);
    tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
    *payload = (u_int8_t*)&l4[tcp_len];
    *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
  } else if(iph->protocol == IPPROTO_UDP && l4_packet_len >= 8) {
    // udp

    workflow->stats.udp_count++;
    *udph = (struct ndpi_udphdr *)l4;
    *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);
    *payload = (u_int8_t*)&l4[sizeof(struct ndpi_udphdr)];
    *payload_len = (l4_packet_len > sizeof(struct ndpi_udphdr)) ? l4_packet_len-sizeof(struct ndpi_udphdr) : 0;
  } else {
    // non tcp/udp protocols
    *sport = *dport = 0;
  }

  flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
  flow.src_ip = iph->saddr, flow.dst_ip = iph->daddr;
  flow.src_port = htons(*sport), flow.dst_port = htons(*dport);
  flow.hashval = hashval = flow.protocol + flow.vlan_id + flow.src_ip + flow.dst_ip + flow.src_port + flow.dst_port;
  idx = hashval % workflow->prefs.num_roots;
  ret = ndpi_tfind(&flow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp);


  /* to avoid two nodes in one binary tree for a flow */
  int is_changed = 0;
  if(ret == NULL) {
    u_int32_t orig_src_ip = flow.src_ip;
    u_int16_t orig_src_port = flow.src_port;
    u_int32_t orig_dst_ip = flow.dst_ip;
    u_int16_t orig_dst_port = flow.dst_port;

    flow.src_ip = orig_dst_ip;
    flow.src_port = orig_dst_port;
    flow.dst_ip = orig_src_ip;
    flow.dst_port = orig_src_port;

    is_changed = 1;

    ret = ndpi_tfind(&flow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp);
  }

  if(ret == NULL) {
    if(workflow->stats.ndpi_flow_count == workflow->prefs.max_ndpi_flows) {
      NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR,
	       "maximum flow count (%u) has been exceeded\n",
	       workflow->prefs.max_ndpi_flows);
      exit(-1);
    } else {
      struct ndpi_flow_info *newflow = (struct ndpi_flow_info*)malloc(sizeof(struct ndpi_flow_info));

      if(newflow == NULL) {
	NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	return(NULL);
      } else
        workflow->num_allocated_flows++;

      memset(newflow, 0, sizeof(struct ndpi_flow_info));
      newflow->hashval = hashval;
      newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
      newflow->src_ip = iph->saddr, newflow->dst_ip = iph->daddr;
      newflow->src_port = htons(*sport), newflow->dst_port = htons(*dport);
      newflow->ip_version = version;

      if(version == IPVERSION) {
	inet_ntop(AF_INET, &newflow->src_ip, newflow->src_name, sizeof(newflow->src_name));
	inet_ntop(AF_INET, &newflow->dst_ip, newflow->dst_name, sizeof(newflow->dst_name));
      } else {
	inet_ntop(AF_INET6, &iph6->ip6_src, newflow->src_name, sizeof(newflow->src_name));
	inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->dst_name, sizeof(newflow->dst_name));
	/* For consistency across platforms replace :0: with :: */
	patchIPv6Address(newflow->src_name), patchIPv6Address(newflow->dst_name);
      }

      if((newflow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT)) == NULL) {
	NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(2): not enough memory\n", __FUNCTION__);
	free(newflow);
	return(NULL);
      } else
	memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

      if((newflow->src_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) {
	NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	free(newflow);
	return(NULL);
      } else
	memset(newflow->src_id, 0, SIZEOF_ID_STRUCT);

      if((newflow->dst_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) {
	NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(4): not enough memory\n", __FUNCTION__);
	free(newflow);
	return(NULL);
      } else
	memset(newflow->dst_id, 0, SIZEOF_ID_STRUCT);

      ndpi_tsearch(newflow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp); /* Add */
      workflow->stats.ndpi_flow_count++;

      *src = newflow->src_id, *dst = newflow->dst_id;

      return newflow;
    }
  } else {
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)ret;

    if(is_changed) {
      if(flow->src_ip == iph->saddr
	 && flow->dst_ip == iph->daddr
	 && flow->src_port == htons(*sport)
	 && flow->dst_port == htons(*dport)
	)
	*src = flow->dst_id, *dst = flow->src_id, *src_to_dst_direction = 0, flow->bidirectional = 1;
      else
	*src = flow->src_id, *dst = flow->dst_id, *src_to_dst_direction = 1;
    }
    else {
      if(flow->src_ip == iph->saddr
	 && flow->dst_ip == iph->daddr
	 && flow->src_port == htons(*sport)
	 && flow->dst_port == htons(*dport)
	)
	*src = flow->src_id, *dst = flow->dst_id, *src_to_dst_direction = 1;
      else
	*src = flow->dst_id, *dst = flow->src_id, *src_to_dst_direction = 0, flow->bidirectional = 1;
    }
    return flow;
  }
}

/* ****************************************************** */

static struct ndpi_flow_info *get_ndpi_flow_info6(struct ndpi_workflow * workflow,
						  u_int16_t vlan_id,
						  const struct ndpi_ipv6hdr *iph6,
						  u_int16_t ip_offset,
						  struct ndpi_tcphdr **tcph,
						  struct ndpi_udphdr **udph,
						  u_int16_t *sport, u_int16_t *dport,
						  struct ndpi_id_struct **src,
						  struct ndpi_id_struct **dst,
						  u_int8_t *proto,
						  u_int8_t **payload,
						  u_int16_t *payload_len,
						  u_int8_t *src_to_dst_direction) {
  struct ndpi_iphdr iph;

  memset(&iph, 0, sizeof(iph));
  iph.version = IPVERSION;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
  iph.protocol = iph6->ip6_hdr.ip6_un1_nxt;

  if(iph.protocol == IPPROTO_DSTOPTS /* IPv6 destination option */) {
    const u_int8_t *options = (const u_int8_t*)iph6 + sizeof(const struct ndpi_ipv6hdr);

    iph.protocol = options[0];
  }

  return(get_ndpi_flow_info(workflow, 6, vlan_id, &iph, iph6, ip_offset,
			    sizeof(struct ndpi_ipv6hdr),
			    ntohs(iph6->ip6_hdr.ip6_un1_plen),
			    tcph, udph, sport, dport,
			    src, dst, proto, payload,
			    payload_len, src_to_dst_direction));
}

/* ****************************************************** */

void process_ndpi_collected_info(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow) {
  if(!flow->ndpi_flow) return;

  snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s",
	   flow->ndpi_flow->host_server_name);

  /* BITTORRENT */
  if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_BITTORRENT) {
    u_int i, j, n = 0;

    for(i=0, j = 0; j < sizeof(flow->bittorent_hash)-1; i++) {
      sprintf(&flow->bittorent_hash[j], "%02x",
	      flow->ndpi_flow->protos.bittorrent.hash[i]);

      j += 2, n += flow->ndpi_flow->protos.bittorrent.hash[i];
    }

    if(n == 0) flow->bittorent_hash[0] = '\0';
  }
  /* MDNS */
  else if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_MDNS) {
    snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.mdns.answer);
  }
  /* UBNTAC2 */
  else if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UBNTAC2) {
    snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.ubntac2.version);
  }
  if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_DNS) {
    /* SSH */
    if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_SSH) {
      snprintf(flow->ssh_ssl.client_info, sizeof(flow->ssh_ssl.client_info), "%s",
	       flow->ndpi_flow->protos.ssh.client_signature);
      snprintf(flow->ssh_ssl.server_info, sizeof(flow->ssh_ssl.server_info), "%s",
	       flow->ndpi_flow->protos.ssh.server_signature);
    }
    /* SSL */
    else if((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_SSL)
	    || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSL)) {
      flow->ssh_ssl.ssl_version = flow->ndpi_flow->protos.stun_ssl.ssl.ssl_version;
      snprintf(flow->ssh_ssl.client_info, sizeof(flow->ssh_ssl.client_info), "%s",
	       flow->ndpi_flow->protos.stun_ssl.ssl.client_certificate);
      snprintf(flow->ssh_ssl.server_info, sizeof(flow->ssh_ssl.server_info), "%s",
	       flow->ndpi_flow->protos.stun_ssl.ssl.server_certificate);
      snprintf(flow->ssh_ssl.server_organization, sizeof(flow->ssh_ssl.server_organization), "%s",
	       flow->ndpi_flow->protos.stun_ssl.ssl.server_organization);      
      snprintf(flow->ssh_ssl.ja3_client, sizeof(flow->ssh_ssl.ja3_client), "%s",
	       flow->ndpi_flow->protos.stun_ssl.ssl.ja3_client);
      snprintf(flow->ssh_ssl.ja3_server, sizeof(flow->ssh_ssl.ja3_server), "%s",
	       flow->ndpi_flow->protos.stun_ssl.ssl.ja3_server);
      flow->ssh_ssl.server_unsafe_cipher = flow->ndpi_flow->protos.stun_ssl.ssl.server_unsafe_cipher;
      flow->ssh_ssl.server_cipher = flow->ndpi_flow->protos.stun_ssl.ssl.server_cipher;
    }
  }

  if(flow->detection_completed && (!flow->check_extra_packets)) {
    if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
      if(workflow->__flow_giveup_callback != NULL)
	workflow->__flow_giveup_callback(workflow, flow, workflow->__flow_giveup_udata);
    } else {
      if(workflow->__flow_detected_callback != NULL)
	workflow->__flow_detected_callback(workflow, flow, workflow->__flow_detected_udata);
    }

    ndpi_free_flow_info_half(flow);
  }
}

/* ****************************************************** */

/**
   Function to process the packet:
   determine the flow of a packet and try to decode it
   @return: 0 if success; else != 0

   @Note: ipsize = header->len - ip_offset ; rawsize = header->len
*/
static struct ndpi_proto packet_processing(struct ndpi_workflow * workflow,
					   const u_int64_t time,
					   u_int16_t vlan_id,
					   const struct ndpi_iphdr *iph,
					   struct ndpi_ipv6hdr *iph6,
					   u_int16_t ip_offset,
					   u_int16_t ipsize, u_int16_t rawsize) {
  struct ndpi_id_struct *src, *dst;
  struct ndpi_flow_info *flow = NULL;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int8_t proto;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int16_t sport, dport, payload_len;
  u_int8_t *payload;
  u_int8_t src_to_dst_direction = 1;
  struct ndpi_proto nproto = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };

  if(iph)
    flow = get_ndpi_flow_info(workflow, IPVERSION, vlan_id, iph, NULL,
			      ip_offset, ipsize,
			      ntohs(iph->tot_len) - (iph->ihl * 4),
			      &tcph, &udph, &sport, &dport,
			      &src, &dst, &proto,
			      &payload, &payload_len, &src_to_dst_direction);
  else
    flow = get_ndpi_flow_info6(workflow, vlan_id, iph6, ip_offset,
			       &tcph, &udph, &sport, &dport,
			       &src, &dst, &proto,
			       &payload, &payload_len, &src_to_dst_direction);

  if(flow != NULL) {
    workflow->stats.ip_packet_count++;
    workflow->stats.total_wire_bytes += rawsize + 24 /* CRC etc */,
      workflow->stats.total_ip_bytes += rawsize;
    ndpi_flow = flow->ndpi_flow;

    if(src_to_dst_direction)
      flow->src2dst_packets++, flow->src2dst_bytes += rawsize;
    else
      flow->dst2src_packets++, flow->dst2src_bytes += rawsize;

    flow->last_seen = time;
  } else { // flow is NULL
    workflow->stats.total_discarded_bytes++;
    return(nproto);
  }

  if(!flow->detection_completed) {
    flow->detected_protocol = ndpi_detection_process_packet(workflow->ndpi_struct, ndpi_flow,
							    iph ? (uint8_t *)iph : (uint8_t *)iph6,
							    ipsize, time, src, dst);
  
    if((flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
       || ((proto == IPPROTO_UDP) && ((flow->src2dst_packets + flow->dst2src_packets) > 8))
       || ((proto == IPPROTO_TCP) && ((flow->src2dst_packets + flow->dst2src_packets) > 10))) {
      /* New protocol detected or give up */
      flow->detection_completed = 1;
    
      /* Check if we should keep checking extra packets */
      if(ndpi_flow && ndpi_flow->check_extra_packets)
	flow->check_extra_packets = 1;

      if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
	flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct, flow->ndpi_flow,
							enable_protocol_guess);
    
      process_ndpi_collected_info(workflow, flow);
    }
  }
  
  return(flow->detected_protocol);
}

/* ****************************************************** */

struct ndpi_proto ndpi_workflow_process_packet(struct ndpi_workflow * workflow,
					       const struct pcap_pkthdr *header,
					       const u_char *packet) {
  /*
   * Declare pointers to packet headers
   */
  /* --- Ethernet header --- */
  const struct ndpi_ethhdr *ethernet;
  /* --- LLC header --- */
  const struct ndpi_llc_header_snap *llc;

  /* --- Cisco HDLC header --- */
  const struct ndpi_chdlc *chdlc;

  /* --- Radio Tap header --- */
  const struct ndpi_radiotap_header *radiotap;
  /* --- Wifi header --- */
  const struct ndpi_wifi_header *wifi;

  /* --- MPLS header --- */
  union mpls {
    uint32_t u32;
    struct ndpi_mpls_header mpls;
  } mpls;

  /** --- IP header --- **/
  struct ndpi_iphdr *iph;
  /** --- IPv6 header --- **/
  struct ndpi_ipv6hdr *iph6;

  struct ndpi_proto nproto = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };

  /* lengths and offsets */
  u_int16_t eth_offset = 0;
  u_int16_t radio_len;
  u_int16_t fc;
  u_int16_t type = 0;
  int wifi_len = 0;
  int pyld_eth_len = 0;
  int check;
  u_int64_t time;
  u_int16_t ip_offset = 0, ip_len;
  u_int16_t frag_off = 0, vlan_id = 0;
  u_int8_t proto = 0;
  u_int32_t label;

  /* counters */
  u_int8_t vlan_packet = 0;

  /* Increment raw packet counter */
  workflow->stats.raw_packet_count++;

  /* setting time */
  time = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);

  /* safety check */
  if(workflow->last_time > time) {
    /* printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_thread_info[thread_id].last_time - time); */
    time = workflow->last_time;
  }
  /* update last time value */
  workflow->last_time = time;

  /*** check Data Link type ***/
  int datalink_type;

#ifdef USE_DPDK
  datalink_type = DLT_EN10MB;
#else
  datalink_type = (int)pcap_datalink(workflow->pcap_handle);
#endif
  
datalink_check:
  switch(datalink_type) {
  case DLT_NULL:
    if(ntohl(*((u_int32_t*)&packet[eth_offset])) == 2)
      type = ETH_P_IP;
    else
      type = ETH_P_IPV6;

    ip_offset = 4 + eth_offset;
    break;

    /* Cisco PPP in HDLC-like framing - 50 */
  case DLT_PPP_SERIAL:
    chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
    ip_offset = sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
    type = ntohs(chdlc->proto_code);
    break;

    /* Cisco PPP - 9 or 104 */
  case DLT_C_HDLC:
  case DLT_PPP:
    chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
    ip_offset = sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
    type = ntohs(chdlc->proto_code);
    break;

    /* IEEE 802.3 Ethernet - 1 */
  case DLT_EN10MB:
    ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
    ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
    check = ntohs(ethernet->h_proto);

    if(check <= 1500)
      pyld_eth_len = check;
    else if(check >= 1536)
      type = check;

    if(pyld_eth_len != 0) {
      llc = (struct ndpi_llc_header_snap *)(&packet[ip_offset]);
      /* check for LLC layer with SNAP extension */
      if(llc->dsap == SNAP || llc->ssap == SNAP) {
	type = llc->snap.proto_ID;
	ip_offset += + 8;
      }
      /* No SNAP extension - Spanning Tree pkt must be discarted */
      else if(llc->dsap == BSTP || llc->ssap == BSTP) {
	goto v4_warning;
      }
    }
    break;

    /* Linux Cooked Capture - 113 */
  case DLT_LINUX_SLL:
    type = (packet[eth_offset+14] << 8) + packet[eth_offset+15];
    ip_offset = 16 + eth_offset;
    break;

    /* Radiotap link-layer - 127 */
  case DLT_IEEE802_11_RADIO:
    radiotap = (struct ndpi_radiotap_header *) &packet[eth_offset];
    radio_len = radiotap->len;

    /* Check Bad FCS presence */
    if((radiotap->flags & BAD_FCS) == BAD_FCS) {
      workflow->stats.total_discarded_bytes +=  header->len;
      return(nproto);
    }

    /* Calculate 802.11 header length (variable) */
    wifi = (struct ndpi_wifi_header*)( packet + eth_offset + radio_len);
    fc = wifi->fc;

    /* check wifi data presence */
    if(FCF_TYPE(fc) == WIFI_DATA) {
      if((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) ||
	 (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc)))
	wifi_len = 26; /* + 4 byte fcs */
    } else   /* no data frames */
      break;

    /* Check ether_type from LLC */
    llc = (struct ndpi_llc_header_snap*)(packet + eth_offset + wifi_len + radio_len);
    if(llc->dsap == SNAP)
      type = ntohs(llc->snap.proto_ID);

    /* Set IP header offset */
    ip_offset = wifi_len + radio_len + sizeof(struct ndpi_llc_header_snap) + eth_offset;
    break;

  case DLT_RAW:
    ip_offset = eth_offset = 0;
    break;

  default:
    /* printf("Unknown datalink %d\n", datalink_type); */
    return(nproto);
  }

  /* check ether type */
  switch(type) {
  case VLAN:
    vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
    type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
    ip_offset += 4;
    vlan_packet = 1;
    // double tagging for 802.1Q
    if(type == 0x8100) {
      vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
      type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
      ip_offset += 4;
    }
    break;
  case MPLS_UNI:
  case MPLS_MULTI:
    mpls.u32 = *((uint32_t *) &packet[ip_offset]);
    mpls.u32 = ntohl(mpls.u32);
    workflow->stats.mpls_count++;
    type = ETH_P_IP, ip_offset += 4;

    while(!mpls.mpls.s) {
      mpls.u32 = *((uint32_t *) &packet[ip_offset]);
      mpls.u32 = ntohl(mpls.u32);
      ip_offset += 4;
    }
    break;
  case PPPoE:
    workflow->stats.pppoe_count++;
    type = ETH_P_IP;
    ip_offset += 8;
    break;
  default:
    break;
  }

  workflow->stats.vlan_count += vlan_packet;

iph_check:
  /* Check and set IP header size and total packet length */
  iph = (struct ndpi_iphdr *) &packet[ip_offset];

  /* just work on Ethernet packets that contain IP */
  if(type == ETH_P_IP && header->caplen >= ip_offset) {
    frag_off = ntohs(iph->frag_off);

    proto = iph->protocol;
    if(header->caplen < header->len) {
      static u_int8_t cap_warning_used = 0;

      if(cap_warning_used == 0) {
	if(!workflow->prefs.quiet_mode)
	  NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_DEBUG, "\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
	cap_warning_used = 1;
      }
    }
  }

  if(iph->version == IPVERSION) {
    ip_len = ((u_int16_t)iph->ihl * 4);
    iph6 = NULL;

    if(iph->protocol == IPPROTO_IPV6) {
      ip_offset += ip_len;
      goto iph_check;
    }

    if((frag_off & 0x1FFF) != 0) {
      static u_int8_t ipv4_frags_warning_used = 0;
      workflow->stats.fragmented_count++;

      if(ipv4_frags_warning_used == 0) {
	if(!workflow->prefs.quiet_mode)
	  NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_DEBUG, "\n\nWARNING: IPv4 fragments are not handled by this demo (nDPI supports them)\n");
	ipv4_frags_warning_used = 1;
      }

      workflow->stats.total_discarded_bytes +=  header->len;
      return(nproto);
    }
  } else if(iph->version == 6) {
    iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    proto = iph6->ip6_hdr.ip6_un1_nxt;
    ip_len = sizeof(struct ndpi_ipv6hdr);

    if(proto == IPPROTO_DSTOPTS /* IPv6 destination option */) {

      u_int8_t *options = (u_int8_t*)&packet[ip_offset+ip_len];
      proto = options[0];
      ip_len += 8 * (options[1] + 1);
    }
    iph = NULL;

  } else {
    static u_int8_t ipv4_warning_used = 0;

  v4_warning:
    if(ipv4_warning_used == 0) {
      if(!workflow->prefs.quiet_mode)
        NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_DEBUG, "\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
      ipv4_warning_used = 1;
    }
    workflow->stats.total_discarded_bytes +=  header->len;
    return(nproto);
  }

  if(workflow->prefs.decode_tunnels && (proto == IPPROTO_UDP)) {
    struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
    u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

    if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
      /* Check if it's GTPv1 */
      u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
      u_int8_t flags = packet[offset];
      u_int8_t message_type = packet[offset+1];

      if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) &&
	 (message_type == 0xFF /* T-PDU */)) {

	ip_offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr)+8; /* GTPv1 header len */
	if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
	if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
	if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

	iph = (struct ndpi_iphdr *) &packet[ip_offset];

	if(iph->version != IPVERSION) {
	  // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)workflow->stats.raw_packet_count);
	  goto v4_warning;
	}
      }
    } else if((sport == TZSP_PORT) || (dport == TZSP_PORT)) {
      /* https://en.wikipedia.org/wiki/TZSP */
      u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
      u_int8_t version = packet[offset];
      u_int8_t type    = packet[offset+1];
      u_int16_t encapsulates = ntohs(*((u_int16_t*)&packet[offset+2]));

      if((version == 1) && (type == 0) && (encapsulates == 1)) {
	u_int8_t stop = 0;

	offset += 4;

	while((!stop) && (offset < header->caplen)) {
	  u_int8_t tag_type = packet[offset];
	  u_int8_t tag_len;

	  switch(tag_type) {
	  case 0: /* PADDING Tag */
	    tag_len = 1;
	    break;
	  case 1: /* END Tag */
	    tag_len = 1, stop = 1;
	    break;
	  default:
	    tag_len = packet[offset+1];
	    break;
	  }

	  offset += tag_len;

	  if(offset >= header->caplen)
	    return(nproto); /* Invalid packet */
	  else {
	    eth_offset = offset;
	    goto datalink_check;
	  }
	}
      }
    }
  }

  /* process the packet */
  return(packet_processing(workflow, time, vlan_id, iph, iph6,
			   ip_offset, header->caplen - ip_offset, header->caplen));
}

/* ********************************************************** */
/*       http://home.thep.lu.se/~bjorn/crc/crc32_fast.c       */
/* ********************************************************** */

static uint32_t crc32_for_byte(uint32_t r) {
  int j;
  for(j = 0; j < 8; ++j)
    r = ((r & 1) ? 0 : (uint32_t)0xEDB88320L) ^ r >> 1;
  return r ^ (uint32_t)0xFF000000L;
}

/* Any unsigned integer type with at least 32 bits may be used as
 * accumulator type for fast crc32-calulation, but unsigned long is
 * probably the optimal choice for most systems. */
typedef unsigned long accum_t;

static void init_tables(uint32_t* table, uint32_t* wtable) {
  size_t i, j, k, w;
  for(i = 0; i < 0x100; ++i)
    table[i] = crc32_for_byte(i);
  for(k = 0; k < sizeof(accum_t); ++k)
    for(i = 0; i < 0x100; ++i) {
      for(j = w = 0; j < sizeof(accum_t); ++j)
	w = table[(uint8_t)(j == k? w ^ i: w)] ^ w >> 8;
      wtable[(k << 8) + i] = w ^ (k? wtable[0]: 0);
    }
}

static void __crc32(const void* data, size_t n_bytes, uint32_t* crc) {
  static uint32_t table[0x100], wtable[0x100*sizeof(accum_t)];
  size_t n_accum = n_bytes/sizeof(accum_t);
  size_t i, j;
  if(!*table)
    init_tables(table, wtable);
  for(i = 0; i < n_accum; ++i) {
    accum_t a = *crc ^ ((accum_t*)data)[i];
    for(j = *crc = 0; j < sizeof(accum_t); ++j)
      *crc ^= wtable[(j << 8) + (uint8_t)(a >> 8*j)];
  }
  for(i = n_accum*sizeof(accum_t); i < n_bytes; ++i)
    *crc = table[(uint8_t)*crc ^ ((uint8_t*)data)[i]] ^ *crc >> 8;
}

u_int32_t ethernet_crc32(const void* data, size_t n_bytes) {
  u_int32_t crc = 0;
  __crc32(data, n_bytes, &crc);
  return crc;
}

/* *********************************************** */

#ifdef USE_DPDK

static const struct rte_eth_conf port_conf_default = {
  .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

/* ************************************ */

int dpdk_port_init(int port, struct rte_mempool *mbuf_pool) {
  struct rte_eth_conf port_conf = port_conf_default;
  const u_int16_t rx_rings = 1, tx_rings = 1;
  int retval;
  u_int16_t q;

  /* 1 RX queue */
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);

  if(retval != 0)
    return retval;

  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if(retval < 0)
      return retval;
  }

  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
    if(retval < 0)
      return retval;
  }

  retval = rte_eth_dev_start(port);

  if(retval < 0)
    return retval;

  rte_eth_promiscuous_enable(port);

  return 0;
}

#endif
