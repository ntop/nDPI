/*
 * ndpi_main.h
 *
 * Copyright (C) 2011-22 - ntop.org
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

#ifndef __NDPI_MAIN_H__
#define __NDPI_MAIN_H__

#include "ndpi_includes.h"
#ifdef NDPI_LIB_COMPILATION
/* for macros NDPI_LOG_* in ndpi_define.h */
#include "ndpi_config.h"
#endif
#include "ndpi_define.h"
#include "ndpi_protocol_ids.h"
#include "ndpi_typedefs.h"
#include "ndpi_api.h"


#ifdef __cplusplus
extern "C" {
#endif

  void *ndpi_tdelete(const void * __restrict, void ** __restrict,
		     int (*)(const void *, const void *));
  void *ndpi_tfind(const void *, void *, int (*)(const void *, const void *));
  void *ndpi_tsearch(const void *, void**, int (*)(const void *, const void *));
  void ndpi_twalk(const void *, void (*)(const void *, ndpi_VISIT, int, void*), void *user_data);
  void ndpi_tdestroy(void *vrootp, void (*freefct)(void *));

  int NDPI_BITMASK_COMPARE(NDPI_PROTOCOL_BITMASK a, NDPI_PROTOCOL_BITMASK b);

  u_int16_t ntohs_ndpi_bytestream_to_number(const u_int8_t * str,
					    u_int16_t max_chars_to_read,
					    u_int16_t * bytes_read);

  u_int32_t ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read,
				      u_int16_t * bytes_read);
  u_int64_t ndpi_bytestream_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read,
					u_int16_t * bytes_read);
  u_int64_t ndpi_bytestream_dec_or_hex_to_number64(const u_int8_t * str,
						   u_int16_t max_chars_to_read,
						   u_int16_t * bytes_read);
  u_int32_t ndpi_bytestream_to_ipv4(const u_int8_t * str, u_int16_t max_chars_to_read,
				    u_int16_t * bytes_read);

  extern void ndpi_set_proto_subprotocols(struct ndpi_detection_module_struct *ndpi_mod,
                                     int protoId, ...);

  extern int ndpi_parse_ip_string(const char *ip_str, ndpi_ip_addr_t *parsed_ip);
  extern char *ndpi_get_ip_string(const ndpi_ip_addr_t * ip, char *buf, u_int buf_len);
  extern u_int8_t ndpi_is_ipv6(const ndpi_ip_addr_t *ip);

  extern void ndpi_search_tcp_or_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);

  /** Checks when the @p payload starts with the string literal @p str.
   * When the string is larger than the payload, check fails.
   * @return non-zero if check succeeded
   */
  int ndpi_match_prefix(const u_int8_t *payload, size_t payload_len,
			const char *str, size_t str_len);

  /* version of ndpi_match_prefix with string literal */
#define ndpi_match_strprefix(payload, payload_len, str)			\
  ndpi_match_prefix((payload), (payload_len), (str), (sizeof(str)-1))

  int ndpi_handle_ipv6_extension_headers(u_int16_t l3len,
					 const u_int8_t ** l4ptr, u_int16_t * l4len,
					 u_int8_t * nxt_hdr);
  
  void ndpi_set_proto_defaults(struct ndpi_detection_module_struct *ndpi_str,
			       u_int8_t is_cleartext, u_int8_t is_app_protocol,
			       ndpi_protocol_breed_t breed,
			       u_int16_t protoId, char *protoName,
			       ndpi_protocol_category_t protoCategory,
			       ndpi_port_range *tcpDefPorts,
			       ndpi_port_range *udpDefPorts);
  void ndpi_set_risk(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
                     ndpi_risk_enum r, char *risk_message);
  void ndpi_unset_risk(struct ndpi_flow_struct *flow, ndpi_risk_enum r);
  int ndpi_isset_risk(struct ndpi_flow_struct *flow, ndpi_risk_enum r);
  int ndpi_is_printable_buffer(u_int8_t const * const buf, size_t len);
  int ndpi_normalize_printable_string(char * const str, size_t len);
  int ndpi_is_valid_hostname(char * const str, size_t len);

#define NDPI_ENTROPY_PLAINTEXT(entropy) (entropy < 4.941f)
#define NDPI_ENTROPY_EXECUTABLE(entropy) (entropy >= 4.941f)
#define NDPI_ENTROPY_EXECUTABLE_PACKED(entropy) (entropy >= 6.677f)
#define NDPI_ENTROPY_EXECUTABLE_ENCRYPTED(entropy) (entropy >= 7.174f)
#define NDPI_ENTROPY_ENCRYPTED_OR_RANDOM(entropy) (entropy >= 7.312f)
  float ndpi_entropy(u_int8_t const * const buf, size_t len);
  char *ndpi_entropy2str(float entropy, char *buf, size_t len);
  void ndpi_entropy2risk(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);

#ifdef __cplusplus
}
#endif

#endif	/* __NDPI_MAIN_H__ */
