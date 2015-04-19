/*
 * ndpi_main.h
 *
 * Copyright (C) 2011-15 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
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

#ifndef __NDPI_MAIN_INCLUDE_FILE__
#define __NDPI_MAIN_INCLUDE_FILE__

#ifndef __KERNEL__
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifndef WIN32
#include <pthread.h>
#endif
#include <ctype.h>
#include <time.h>
#endif


#ifndef WIN32
#ifndef __KERNEL__
#include <sys/time.h>
#endif

#if !defined __APPLE__ && !defined __FreeBSD__ && !defined __NetBSD__ && !defined __OpenBSD__

#ifndef __KERNEL__
#include <endian.h>
#include <byteswap.h>
#else
#include <asm/byteorder.h>
#include <linux/ctype.h>
#endif

#endif

/* default includes */

#ifndef __KERNEL__
#include <sys/param.h>
#include <limits.h>
#endif
#endif

#include "ndpi_win32.h"
#include "ndpi_unix.h"
#include "ndpi_define.h"
#include "ndpi_protocol_ids.h"
#include "ndpi_typedefs.h"
#include "ndpi_protocols.h"


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

u_int16_t ntohs_ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);

u_int32_t ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);
u_int64_t ndpi_bytestream_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);
u_int32_t ndpi_bytestream_dec_or_hex_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);
u_int64_t ndpi_bytestream_dec_or_hex_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);
u_int32_t ndpi_bytestream_to_ipv4(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);


void ndpi_int_add_connection(struct ndpi_detection_module_struct *ndpi_struct,                             
                             struct ndpi_flow_struct *flow,
                             u_int16_t detected_protocol, ndpi_protocol_type_t protocol_type);


/* function to parse a packet which has line based information into a line based structure
 * this function will also set some well known line pointers like:
 *  - host, user agent, empty line,....
 */
extern void ndpi_parse_packet_line_info(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
extern void ndpi_parse_packet_line_info_any(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
extern u_int16_t ndpi_check_for_email_address(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int16_t counter);
extern void ndpi_int_change_packet_protocol(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					    u_int16_t detected_protocol, ndpi_protocol_type_t protocol_type);
extern void ndpi_int_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow,
				     u_int16_t detected_protocol,
				     ndpi_protocol_type_t protocol_type);
extern void ndpi_set_proto_defaults(struct ndpi_detection_module_struct *ndpi_mod,
				    ndpi_protocol_breed_t protoBreed, u_int16_t protoId,
				    u_int16_t tcp_alias_protoId[2], u_int16_t udp_alias_protoId[2],
				    char *protoName,
				    ndpi_port_range *tcpDefPorts, ndpi_port_range *udpDefPorts);
extern void ndpi_int_reset_packet_protocol(struct ndpi_packet_struct *packet);
extern void ndpi_int_reset_protocol(struct ndpi_flow_struct *flow);
extern int ndpi_packet_src_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip);
extern int ndpi_packet_dst_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip);
extern void ndpi_packet_src_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip);
extern void ndpi_packet_dst_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip);
extern char *ndpi_get_ip_string(struct ndpi_detection_module_struct *ndpi_struct, const ndpi_ip_addr_t * ip);
extern char *ndpi_get_packet_src_ip_string(struct ndpi_detection_module_struct *ndpi_struct,
					   const struct ndpi_packet_struct *packet);
extern char* ndpi_get_proto_by_id(struct ndpi_detection_module_struct *ndpi_mod, u_int id);
extern u_int16_t ndpi_guess_protocol_id(struct ndpi_detection_module_struct *ndpi_struct,
					u_int8_t proto, u_int16_t sport, u_int16_t dport);
extern int ndpi_get_protocol_id_master_proto(struct ndpi_detection_module_struct *ndpi_struct,
					     u_int16_t protocol_id,
					     u_int16_t** tcp_master_proto,
					     u_int16_t** udp_master_proto);

extern u_int8_t ndpi_net_match(u_int32_t ip_to_check,
			       u_int32_t net,
			       u_int32_t num_bits);

extern u_int8_t ndpi_ips_match(u_int32_t src, u_int32_t dst,
			       u_int32_t net, u_int32_t num_bits);

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  void ndpi_debug_get_last_log_function_line(struct ndpi_detection_module_struct *ndpi_struct,
					     const char **file, const char **func, u_int32_t * line);
#endif

#include "ndpi_api.h"

#endif	/* __NDPI_MAIN_INCLUDE_FILE__ */
