/*
 * ndpi_api.h
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


#ifndef __NDPI_PUBLIC_FUNCTIONS_H__
#define __NDPI_PUBLIC_FUNCTIONS_H__

#include "ndpi_main.h"

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * This function returns the size of the flow struct
   * @return the size of the flow struct
   */
  u_int32_t ndpi_detection_get_sizeof_ndpi_flow_struct(void);

  /**
   * This function returns the size of the id struct
   * @return the size of the id struct
   */
  u_int32_t ndpi_detection_get_sizeof_ndpi_id_struct(void);


  /* Public malloc/free */
  void* ndpi_malloc(unsigned long size);
  void* ndpi_calloc(unsigned long count, unsigned long size);
  void  ndpi_free(void *ptr);
  void *ndpi_realloc(void *ptr, size_t old_size, size_t new_size);
  char *ndpi_strdup(const char *s);
  /*
   * Find the first occurrence of find in s, where the search is limited to the
   * first slen characters of s.
   */
  char* ndpi_strnstr(const char *s, const char *find, size_t slen);

  /**
   * This function returns the nDPI protocol id for IP-based protocol detection
   */
  u_int16_t ndpi_network_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, struct in_addr *pin);

  /**
   * Same as ndpi_network_ptree_match
   */
  u_int16_t ndpi_host_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t host);

  /**
   * This function returns a new initialized detection module.
   * @param ticks_per_second the timestamp resolution per second (like 1000 for millisecond resolution)
   * @param ndpi_malloc function pointer to a memory allocator
   * @param ndpi_debug_printf a function pointer to a debug output function, use NULL in productive envionments
   * @return the initialized detection module
   */
  struct ndpi_detection_module_struct *ndpi_init_detection_module(u_int32_t ticks_per_second,
								  void* (*__ndpi_malloc)(unsigned long size),
								  void  (*__ndpi_free)(void *ptr),
								  ndpi_debug_function_ptr ndpi_debug_printf);

  
  /**
   * This function frees the memory allocated in the specified flow
   * @param flow to free
   */
  void ndpi_free_flow(struct ndpi_flow_struct *flow);

  /**
   * This function enables cache support in nDPI used for some protocol such as Skype
   * @param cache host name
   * @param cache port
   */
  void ndpi_enable_cache(struct ndpi_detection_module_struct *ndpi_mod, char* host, u_int port);

  /**
   * This function destroys the detection module
   * @param ndpi_struct the to clearing detection module
   * @param ndpi_free function pointer to a memory free function
   */
  void
  ndpi_exit_detection_module(struct ndpi_detection_module_struct
			     *ndpi_struct, void (*ndpi_free) (void *ptr));

  /**
   * This function sets the protocol bitmask2
   * @param ndpi_struct the detection module
   * @param detection_bitmask the protocol bitmask
   */
  void
  ndpi_set_protocol_detection_bitmask2(struct ndpi_detection_module_struct *ndpi_struct,
				       const NDPI_PROTOCOL_BITMASK * detection_bitmask);
  /**
   * This function will processes one packet and returns the ID of the detected protocol.
   * This is the main packet processing function.
   *
   * @param ndpi_struct the detection module
   * @param flow void pointer to the connection state machine
   * @param packet the packet as unsigned char pointer with the length of packetlen. the pointer must point to the Layer 3 (IP header)
   * @param packetlen the length of the packet
   * @param current_tick the current timestamp for the packet
   * @param src void pointer to the source subscriber state machine
   * @param dst void pointer to the destination subscriber state machine
   * @return returns the detected ID of the protocol
   */
  unsigned int
  ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				const unsigned char *packet,
				const unsigned short packetlen,
				const u_int64_t current_tick,
				struct ndpi_id_struct *src,
				struct ndpi_id_struct *dst);

#define NDPI_DETECTION_ONLY_IPV4 ( 1 << 0 )
#define NDPI_DETECTION_ONLY_IPV6 ( 1 << 1 )

  /**
   * query the pointer to the layer 4 packet
   *
   * @param l3 pointer to the layer 3 data
   * @param l3_len length of the layer 3 data
   * @param l4_return filled with the pointer the layer 4 data if return value == 0, undefined otherwise
   * @param l4_len_return filled with the length of the layer 4 data if return value == 0, undefined otherwise
   * @param l4_protocol_return filled with the protocol of the layer 4 data if return value == 0, undefined otherwise
   * @param flags limit operation on ipv4 or ipv6 packets, possible values are NDPI_DETECTION_ONLY_IPV4 or NDPI_DETECTION_ONLY_IPV6; 0 means any
   * @return 0 if correct layer 4 data could be found, != 0 otherwise
   */
  u_int8_t ndpi_detection_get_l4(const u_int8_t * l3, u_int16_t l3_len, const u_int8_t ** l4_return, u_int16_t * l4_len_return,
				 u_int8_t * l4_protocol_return, u_int32_t flags);
  /**
   * returns the real protocol for the flow of the last packet given to the detection.
   * if no real protocol could be found, the unknown protocol will be returned.
   *
   * @param ndpi_struct the detection module
   * @return the protocol id of the last real protocol found in the protocol history of the flow
   */
  u_int16_t ndpi_detection_get_real_protocol_of_flow(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);

  /**
   * returns true if the protocol history of the flow of the last packet given to the detection
   * contains the given protocol.
   *
   * @param ndpi_struct the detection module
   * @return 1 if protocol has been found, 0 otherwise
   */
  u_int8_t ndpi_detection_flow_protocol_history_contains_protocol(struct ndpi_detection_module_struct *ndpi_struct,
								  struct ndpi_flow_struct *flow,
								  u_int16_t protocol_id);
  unsigned int ndpi_find_port_based_protocol(struct ndpi_detection_module_struct *ndpi_struct,
					     u_int8_t proto, u_int32_t shost, u_int16_t sport, u_int32_t dhost, u_int16_t dport);
  unsigned int ndpi_guess_undetected_protocol(struct ndpi_detection_module_struct *ndpi_struct,
					      u_int8_t proto, u_int32_t shost, u_int16_t sport, u_int32_t dhost, u_int16_t dport);
  int ndpi_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow, char *string_to_match, u_int string_to_match_len);
  int ndpi_match_content_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow,
				     char *string_to_match, u_int string_to_match_len);
  int ndpi_match_bigram(struct ndpi_detection_module_struct *ndpi_struct, 
			ndpi_automa *automa, char *bigram_to_match);
  char* ndpi_get_proto_name(struct ndpi_detection_module_struct *mod, u_int16_t proto_id);
  ndpi_protocol_breed_t ndpi_get_proto_breed(struct ndpi_detection_module_struct *ndpi_struct, u_int16_t proto);
  char* ndpi_get_proto_breed_name(struct ndpi_detection_module_struct *ndpi_struct, ndpi_protocol_breed_t breed_id);
  int ndpi_get_protocol_id(struct ndpi_detection_module_struct *ndpi_mod, char *proto);
  void ndpi_dump_protocols(struct ndpi_detection_module_struct *mod);
  int matchStringProtocol(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow,
			  char *string_to_match, u_int string_to_match_len);

  int ndpi_load_protocols_file(struct ndpi_detection_module_struct *ndpi_mod, char* path);
  u_int ndpi_get_num_supported_protocols(struct ndpi_detection_module_struct *ndpi_mod);
  char* ndpi_revision(void);
  void ndpi_set_automa(struct ndpi_detection_module_struct *ndpi_struct, void* automa);

#define ADD_TO_DETECTION_BITMASK             1
#define NO_ADD_TO_DETECTION_BITMASK          0
#define SAVE_DETECTION_BITMASK_AS_UNKNOWN    1
#define NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN 0

  /**
   * This function sets a single protocol bitmask
   * @param label Protocol name
   * @param ndpi_struct the detection module
   * @param detection_bitmask the protocol bitmask
   * @param idx the index of the callback_buffer
   * @param func void function point of the protocol search
   * @param ndpi_selection_bitmask the protocol selected bitmask
   * @param b_save_bitmask_unknow set true if you want save the detection bitmask as unknow
   * @param b_add_detection_bitmask set true if you want add the protocol bitmask to the detection bitmask
   * NB: this function does not increment the index of the callback_buffer
   */
  void ndpi_set_bitmask_protocol_detection(char * label, struct ndpi_detection_module_struct *ndpi_struct,
					   const NDPI_PROTOCOL_BITMASK * detection_bitmask,
					   const u_int32_t idx,
					   u_int16_t ndpi_protocol_id,
					   void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow),
					   const NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask,
					   u_int8_t b_save_bitmask_unknow,
					   u_int8_t b_add_detection_bitmask);

#ifdef NDPI_PROTOCOL_HTTP
  /*
    API used to retrieve information for HTTP flows
  */
  ndpi_http_method ndpi_get_http_method(struct ndpi_detection_module_struct *ndpi_mod, 
					struct ndpi_flow_struct *flow);
  
  char* ndpi_get_http_url(struct ndpi_detection_module_struct *ndpi_mod,
			struct ndpi_flow_struct *flow);
  
  char* ndpi_get_http_content_type(struct ndpi_detection_module_struct *ndpi_mod, 
				 struct ndpi_flow_struct *flow);
#endif

#ifdef NDPI_PROTOCOL_TOR
  int ndpi_is_ssl_tor(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow, char *certificate);
#endif

#ifdef __cplusplus
}
#endif
#endif
