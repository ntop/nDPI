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
#include "ndpi_define.h"
#include "ndpi_protocol_ids.h"
#include "ndpi_typedefs.h"
#include "ndpi_api.h"
#include "ndpi_protocols.h"

/* used by ndpi_set_proto_subprotocols */
#define NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS (-1)
#define NDPI_PROTOCOL_MATCHED_BY_CONTENT (-2)

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
  int NDPI_BITMASK_IS_EMPTY(NDPI_PROTOCOL_BITMASK a);
  void NDPI_DUMP_BITMASK(NDPI_PROTOCOL_BITMASK a);

  extern u_int8_t ndpi_net_match(u_int32_t ip_to_check,
				 u_int32_t net,
				 u_int32_t num_bits);

  extern u_int8_t ndpi_ips_match(u_int32_t src, u_int32_t dst,
				 u_int32_t net, u_int32_t num_bits);

  u_int16_t ntohs_ndpi_bytestream_to_number(const u_int8_t * str,
					    u_int16_t max_chars_to_read,
					    u_int16_t * bytes_read);

  u_int32_t ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read,
				      u_int16_t * bytes_read);
  u_int64_t ndpi_bytestream_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read,
					u_int16_t * bytes_read);
  u_int32_t ndpi_bytestream_dec_or_hex_to_number(const u_int8_t * str,
						 u_int16_t max_chars_to_read,
						 u_int16_t * bytes_read);
  u_int64_t ndpi_bytestream_dec_or_hex_to_number64(const u_int8_t * str,
						   u_int16_t max_chars_to_read,
						   u_int16_t * bytes_read);
  u_int32_t ndpi_bytestream_to_ipv4(const u_int8_t * str, u_int16_t max_chars_to_read,
				    u_int16_t * bytes_read);

  void ndpi_set_detected_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  u_int16_t upper_detected_protocol,
				  u_int16_t lower_detected_protocol,
				  ndpi_confidence_t confidence);

  extern void ndpi_parse_packet_line_info(struct ndpi_detection_module_struct *ndpi_struct,
					  struct ndpi_flow_struct *flow);
  extern void ndpi_parse_packet_line_info_any(struct ndpi_detection_module_struct *ndpi_struct,
					      struct ndpi_flow_struct *flow);

  extern u_int16_t ndpi_check_for_email_address(struct ndpi_detection_module_struct *ndpi_struct,
						struct ndpi_flow_struct *flow, u_int16_t counter);

  extern void ndpi_int_change_category(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow,
				       ndpi_protocol_category_t protocol_category);

  extern void ndpi_set_proto_subprotocols(struct ndpi_detection_module_struct *ndpi_mod,
				      int protoId, ...);

  extern void ndpi_set_proto_defaults(struct ndpi_detection_module_struct *ndpi_mod,
				      u_int8_t is_cleartext,
				      ndpi_protocol_breed_t protoBreed, u_int16_t protoId, char *protoName,
				      ndpi_protocol_category_t protoCategory,
				      ndpi_port_range *tcpDefPorts,
				      ndpi_port_range *udpDefPorts);

  extern void ndpi_int_reset_protocol(struct ndpi_flow_struct *flow);

  extern int ndpi_packet_src_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip);
  extern int ndpi_packet_dst_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip);
  extern void ndpi_packet_src_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip);
  extern void ndpi_packet_dst_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip);

  extern int ndpi_parse_ip_string(const char *ip_str, ndpi_ip_addr_t *parsed_ip);
  extern char *ndpi_get_ip_string(const ndpi_ip_addr_t * ip, char *buf, u_int buf_len);
  extern u_int8_t ndpi_is_ipv6(const ndpi_ip_addr_t *ip);

  extern char* ndpi_get_proto_by_id(struct ndpi_detection_module_struct *ndpi_mod, u_int id);
  u_int16_t ndpi_get_proto_by_name(struct ndpi_detection_module_struct *ndpi_mod, const char *name);

  extern u_int16_t ndpi_guess_protocol_id(struct ndpi_detection_module_struct *ndpi_struct,
					  struct ndpi_flow_struct *flow,
					  u_int8_t proto, u_int16_t sport, u_int16_t dport,
					  u_int8_t *user_defined_proto);

  extern u_int8_t ndpi_is_proto(ndpi_protocol proto, u_int16_t p);

  extern u_int16_t ndpi_get_lower_proto(ndpi_protocol p);

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  void ndpi_debug_get_last_log_function_line(struct ndpi_detection_module_struct *ndpi_struct,
					     const char **file, const char **func, u_int32_t * line);
#endif

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
  void ndpi_set_risk(struct ndpi_detection_module_struct *ndpi_str,
		     struct ndpi_flow_struct *flow, ndpi_risk_enum r);
  int ndpi_isset_risk(struct ndpi_detection_module_struct *ndpi_str,
		      struct ndpi_flow_struct *flow, ndpi_risk_enum r);
  int ndpi_is_printable_string(char * const str, size_t len);
#define NDPI_ENTROPY_ENCRYPTED_OR_RANDOM(entropy) (entropy > 7.0f)
  float ndpi_entropy(u_int8_t const * const buf, size_t len);
  void load_common_alpns(struct ndpi_detection_module_struct *ndpi_str);
  u_int8_t is_a_common_alpn(struct ndpi_detection_module_struct *ndpi_str,
			    const char *alpn_to_check, u_int alpn_to_check_len);    

  char *ndpi_hostname_sni_set(struct ndpi_flow_struct *flow, const u_int8_t *value, size_t value_len);

#ifdef __cplusplus
}
#endif

#endif	/* __NDPI_MAIN_H__ */
