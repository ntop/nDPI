/*
 * ndpi_api.h
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


#ifndef __NDPI_API_H__
#define __NDPI_API_H__

#include "ndpi_main.h"

#ifdef __cplusplus
extern "C" {
#endif

  /* The #define below is used for apps that dynamically link with nDPI to make
     sure that datastructures and in sync across versions
  */
#define NDPI_API_VERSION                      1

#define SIZEOF_ID_STRUCT                      ( sizeof(struct ndpi_id_struct)   )
#define SIZEOF_FLOW_STRUCT                    ( sizeof(struct ndpi_flow_struct) )

#define NDPI_DETECTION_ONLY_IPV4              ( 1 << 0 )
#define NDPI_DETECTION_ONLY_IPV6              ( 1 << 1 )

#define ADD_TO_DETECTION_BITMASK              1
#define NO_ADD_TO_DETECTION_BITMASK           0
#define SAVE_DETECTION_BITMASK_AS_UNKNOWN     1
#define NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN  0


  /**
   * Check if a string is encoded with punycode
   * ( https://tools.ietf.org/html/rfc3492 )
   *
   * @par    buff = pointer to the string to ckeck
   * @par    len  = len of the string
   * @return 1 if the string is punycoded;
   *         else 0
   *
   */
  int ndpi_check_punycode_string(char *buff, int len);


  /**
   * Get the size of the flow struct
   *
   * @return the size of the flow struct
   *
   */
  u_int32_t ndpi_detection_get_sizeof_ndpi_flow_struct(void);


  /**
   * Get the size of the id struct
   *
   * @return the size of the id struct
   *
   */
  u_int32_t ndpi_detection_get_sizeof_ndpi_id_struct(void);

  /**
   * nDPI personal allocation and free functions
  **/
  void * ndpi_malloc(size_t size);
  void * ndpi_calloc(unsigned long count, size_t size);
  void * ndpi_realloc(void *ptr, size_t old_size, size_t new_size);
  char * ndpi_strdup(const char *s);
  void   ndpi_free(void *ptr);
  void * ndpi_flow_malloc(size_t size);
  void   ndpi_flow_free(void *ptr);

  /**
   * Search the first occurrence of substring -find- in -s-
   * The search is limited to the first -slen- characters of the string
   *
   * @par    s     = string to parse
   * @par    find  = string to match with -s-
   * @par    slen  = max length to match between -s- and -find-
   * @return a pointer to the beginning of the located substring;
   *         NULL if the substring is not found
   *
   */
  char* ndpi_strnstr(const char *s, const char *find, size_t slen);

  /**
   * Same as ndpi_strnstr but case insensitive
   *
   * @par    s     = string to parse
   * @par    find  = string to match with -s-
   * @par    slen  = max length to match between -s- and -find-
   * @return a pointer to the beginning of the located substring;
   *         NULL if the substring is not found
   *
   */
  char* ndpi_strncasestr(const char *s, const char *find, size_t slen);

  /**
   * Returns the nDPI protocol id for IP-based protocol detection
   *
   * @par    ndpi_struct  = the struct created for the protocol detection
   * @par    pin          = IP host address (MUST BE in network byte order):
   *                        See man(7) ip for details
   * @return the nDPI protocol ID
   *
   */
  u_int16_t ndpi_network_ptree_match(struct ndpi_detection_module_struct *ndpi_struct,
				     struct in_addr *pin);

  /**
   * Init single protocol match
   *
   * @par ndpi_mod  = the struct created for the protocol detection
   * @par match     = the struct passed to match the protocol
   *
   */
  void ndpi_init_protocol_match(struct ndpi_detection_module_struct *ndpi_mod,
				ndpi_protocol_match *match);

  /**
   * Returns a new initialized detection module
   * Note that before you can use it you can still load
   * hosts and do other things. As soon as you are ready to use
   * it do not forget to call first ndpi_finalize_initalization()
   *
   * @par prefs = load preferences
   * @return  the initialized detection module
   *
   */
  struct ndpi_detection_module_struct *ndpi_init_detection_module(ndpi_init_prefs prefs);

  /**
   * Completes the initialization (2nd step)
   *
   * @return  the initialized detection module
   *
   */
  void ndpi_finalize_initalization(struct ndpi_detection_module_struct *ndpi_str);

  /**
   * Frees the memory allocated in the specified flow
   *
   * @par flow  = the flow to deallocate
   *
   */
  void ndpi_free_flow(struct ndpi_flow_struct *flow);

  /**
   * Enables cache support.
   * In nDPI is used for some protocol (i.e. Skype)
   *
   * @par ndpi_mod  = the struct created for the protocol detection
   * @par host      = string for the host name
   * @par port      = unsigned int for the port number
   *
   */
  void ndpi_enable_cache(struct ndpi_detection_module_struct *ndpi_mod,
			 char* host, u_int port);

  /**
   * Destroys the detection module
   *
   * @par ndpi_struct  = the struct to clearing for the detection module
   *
   */
  void ndpi_exit_detection_module(struct ndpi_detection_module_struct *ndpi_struct);

  /**
   * Sets a single protocol bitmask
   * This function does not increment the index of the callback_buffer
   *
   * @par label                    = string for the protocol name
   * @par ndpi_struct              = the detection module
   * @par detection_bitmask        = the protocol bitmask
   * @par idx                      = the index of the callback_buffer
   * @par func                     = function pointer of the protocol search
   * @par ndpi_selection_bitmask   = the protocol selected bitmask
   * @par b_save_bitmask_unknow    = if set as "true" save the detection bitmask as unknow
   * @par b_add_detection_bitmask  = if set as "true" add the protocol bitmask to the detection bitmask
   *
   */
  void ndpi_set_bitmask_protocol_detection(char *label,
					   struct ndpi_detection_module_struct *ndpi_struct,
					   const NDPI_PROTOCOL_BITMASK *detection_bitmask,
					   const u_int32_t idx,
					   u_int16_t ndpi_protocol_id,
					   void (*func) (struct ndpi_detection_module_struct *,
							 struct ndpi_flow_struct *flow),
					   const NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask,
					   u_int8_t b_save_bitmask_unknow,
					   u_int8_t b_add_detection_bitmask);

  /**
   * Sets the protocol bitmask2
   *
   * @par ndpi_struct        = the detection module
   * @par detection_bitmask  = the protocol bitmask to set
   *
   */
  void ndpi_set_protocol_detection_bitmask2(struct ndpi_detection_module_struct *ndpi_struct,
					    const NDPI_PROTOCOL_BITMASK * detection_bitmask);
  
    /**
   *  Function to be called before we give up with detection for a given flow.
   *  This function reduces the NDPI_UNKNOWN_PROTOCOL detection
   *
   * @par    ndpi_struct  = the detection module
   * @par    flow         = the flow given for the detection module
   * @par    enable_guess = guess protocol if unknown
   * @par    protocol_was_guessed = 1 if the protocol was guesses (requires enable_guess = 1), 0 otherwise
   * @return the detected protocol even if the flow is not completed;
   *
   */
  ndpi_protocol ndpi_detection_giveup(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow,
				      u_int8_t enable_guess,
				      u_int8_t *protocol_was_guessed);

  /**
   * Processes an extra packet in order to get more information for a given protocol
   * (like SSL getting both client and server certificate even if we already know after
   * seeing the client certificate what the protocol is)
   *
   * @par    ndpi_struct   = the detection module
   * @par    flow          = pointer to the connection state machine
   * @par    packet        = unsigned char pointer to the Layer 3 (IP header)
   * @par    packetlen     = the length of the packet
   * @par    current_tick  = the current timestamp for the packet
   * @par    src           = pointer to the source subscriber state machine
   * @par    dst           = pointer to the destination subscriber state machine
   * @return void
   *
   */
  void ndpi_process_extra_packet(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow,
				 const unsigned char *packet,
				 const unsigned short packetlen,
				 const u_int64_t current_tick,
				 struct ndpi_id_struct *src,
				 struct ndpi_id_struct *dst);

  /**
   * Processes one packet and returns the ID of the detected protocol.
   * This is the MAIN PACKET PROCESSING FUNCTION.
   *
   * @par    ndpi_struct   = the detection module
   * @par    flow          = pointer to the connection state machine
   * @par    packet        = unsigned char pointer to the Layer 3 (IP header)
   * @par    packetlen     = the length of the packet
   * @par    current_tick  = the current timestamp for the packet
   * @par    src           = pointer to the source subscriber state machine
   * @par    dst           = pointer to the destination subscriber state machine
   * @return the detected ID of the protocol
   *
   */
  ndpi_protocol ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_struct,
					      struct ndpi_flow_struct *flow,
					      const unsigned char *packet,
					      const unsigned short packetlen,
					      const u_int64_t current_tick,
					      struct ndpi_id_struct *src,
					      struct ndpi_id_struct *dst);
  /**
   * Get the main protocol of the passed flows for the detected module
   *
   *
   * @par    ndpi_struct  = the detection module
   * @par    flow         = the flow given for the detection module
   * @return the ID of the master protocol detected
   *
   */
  u_int16_t ndpi_get_flow_masterprotocol(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow);
  
  /**
   * API call that is called internally by ndpi_detection_process_packet or by apps
   * that want to avoid calling ndpi_detection_process_packet as they have already
   * parsed the packet and thus want to avoid this.
   *
   *
   * @par    ndpi_struct              = the detection module
   * @par    flow                     = the flow given for the detection module
   * @par    ndpi_selection_bitmask   = the protocol selected bitmask
   *
   */
  void ndpi_check_flow_func(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow,
			    NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet);

  /**
   * Query the pointer to the layer 4 packet
   *
   * @par    l3 = pointer to the layer 3 data
   * @par    l3_len = length of the layer 3 data
   * @par    l4_return = address to the pointer of the layer 4 data if return value == 0, else undefined
   * @par    l4_len_return = length of the layer 4 data if return value == 0, else undefined
   * @par    l4_protocol_return = protocol of the layer 4 data if return value == 0, undefined otherwise
   * @par    flags = limit operation on ipv4 or ipv6 packets. Possible values: NDPI_DETECTION_ONLY_IPV4 - NDPI_DETECTION_ONLY_IPV6 - 0 (any)
   * @return 0 if layer 4 data could be found correctly;
             else != 0
   *
   */
  u_int8_t ndpi_detection_get_l4(const u_int8_t *l3, u_int16_t l3_len, const u_int8_t **l4_return, u_int16_t *l4_len_return,
				 u_int8_t *l4_protocol_return, u_int32_t flags);

  /**
   * Search and return the protocol based on matched ports
   *
   * @par    ndpi_struct  = the detection module
   * @par    shost        = source address in host byte order
   * @par    sport        = source port number
   * @par    dhost        = destination address in host byte order
   * @par    dport        = destination port number
   * @return the struct ndpi_protocol that match the port base protocol
   *
   */
  ndpi_protocol ndpi_find_port_based_protocol(struct ndpi_detection_module_struct *ndpi_struct/* , u_int8_t proto */,
					      u_int32_t shost,
					      u_int16_t sport,
					      u_int32_t dhost,
					      u_int16_t dport);
  /**
   * Search and return the protocol guessed that is undetected
   *
   * @par    ndpi_struct  = the detection module
   * @par    flow         = the flow we're trying to guess, NULL if not available
   * @par    proto        = the l4 protocol number
   * @par    shost        = source address in host byte order
   * @par    sport        = source port number
   * @par    dhost        = destination address in host byte order
   * @par    dport        = destination port number
   * @return the struct ndpi_protocol that match the port base protocol
   *
   */
  ndpi_protocol ndpi_guess_undetected_protocol(struct ndpi_detection_module_struct *ndpi_struct,
					       struct ndpi_flow_struct *flow,
					       u_int8_t proto,
					       u_int32_t shost,
					       u_int16_t sport,
					       u_int32_t dhost,
					       u_int16_t dport);
  /**
   * Check if the string passed match with a protocol
   *
   * @par    ndpi_struct         = the detection module
   * @par    string_to_match     = the string to match
   * @par    string_to_match_len = the length of the string
   * @par    ret_match           = completed returned match information
   * @par    is_host_match       = value of the second field of struct ndpi_automa
   * @return the ID of the matched subprotocol
   *
   */
  int ndpi_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				    char *string_to_match,
				    u_int string_to_match_len,
				    ndpi_protocol_match_result *ret_match,
				    u_int8_t is_host_match);
  /**
   * Check if the host passed match with a protocol
   *
   * @par    ndpi_struct         = the detection module
   * @par    flow                = the flow where match the host
   * @par    string_to_match     = the string to match
   * @par    string_to_match_len = the length of the string
   * @par    ret_match           = completed returned match information
   * @par    master_protocol_id  = value of the ID associated to the master protocol detected
   * @return the ID of the matched subprotocol
   *
   */
  u_int16_t ndpi_match_host_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow,
					char *string_to_match,
					u_int string_to_match_len,
					ndpi_protocol_match_result *ret_match,
					u_int16_t master_protocol_id);  

  /**
   * Check if the string content passed match with a protocol
   *
   * @par    ndpi_struct         = the detection module
   * @par    flow                = the flow where match the host
   * @par    string_to_match     = the string to match
   * @par    string_to_match_len = the length of the string
   * @par    ret_match           = completed returned match information
   * @par    master_protocol_id  = value of the ID associated to the master protocol detected
   * @return the ID of the matched subprotocol
   *
   */
  u_int16_t ndpi_match_content_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow,
					   char *string_to_match,
					   u_int string_to_match_len,
					   ndpi_protocol_match_result *ret_match,
					   u_int16_t master_protocol_id);
  /**
   * Exclude protocol from search
   *
   * @par    ndpi_struct         = the detection module
   * @par    flow                = the flow where match the host
   * @par    master_protocol_id  = value of the ID associated to the master protocol detected
   *
   */
  void ndpi_exclude_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  u_int16_t master_protocol_id,
				  const char *_file, const char *_func,int _line);
  /**
   * Check if the string -bigram_to_match- match with a bigram of -automa-
   *
   * @par     ndpi_mod         = the detection module
   * @par     automa           = the struct ndpi_automa for the bigram
   * @par     bigram_to_match  = the bigram string to match
   * @return  0
   *
   */
  int ndpi_match_bigram(struct ndpi_detection_module_struct *ndpi_mod,
			ndpi_automa *automa,
			char *bigram_to_match);

  /**
   * Write the protocol name in the buffer -buf- as master_protocol.protocol
   *
   * @par     ndpi_mod      = the detection module
   * @par     proto         = the struct ndpi_protocol contain the protocols name
   * @par     buf           = the buffer to write the name of the protocols
   * @par     buf_len       = the length of the buffer
   * @return  the buffer contains the master_protocol and protocol name
   *
   */
  char* ndpi_protocol2name(struct ndpi_detection_module_struct *ndpi_mod,
			   ndpi_protocol proto, char *buf, u_int buf_len);

  /**
   * Same as ndpi_protocol2name() with the difference that the numeric protocol
   * name is returned
   *
   * @par     ndpi_mod      = the detection module
   * @par     proto         = the struct ndpi_protocol contain the protocols name
   * @par     buf           = the buffer to write the name of the protocols
   * @par     buf_len       = the length of the buffer
   * @return  the buffer contains the master_protocol and protocol name
   *
   */
  char* ndpi_protocol2id(struct ndpi_detection_module_struct *ndpi_mod,
			 ndpi_protocol proto, char *buf, u_int buf_len);

  /**
   * Find out if a given category is custom/user-defined
   *
   * @par     category      = the category associated to the protocol
   * @return  1 if this is a custom user category, 0 otherwise
   *
   */
  int ndpi_is_custom_category(ndpi_protocol_category_t category);

  /**
   * Overwrite a protocol category defined by nDPI with the custom category
   *
   * @par     ndpi_mod      = the detection module
   * @par     protoId       = the protocol identifier to overwrite
   * @par     breed         = the breed to be associated to the protocol
   *
   */
  void ndpi_set_proto_breed(struct ndpi_detection_module_struct *ndpi_mod,
			    u_int16_t protoId, ndpi_protocol_breed_t breed);

  /**
   * Overwrite a protocol category defined by nDPI with the custom category
   *
   * @par     ndpi_mod      = the detection module
   * @par     protoId       = the protocol identifier to overwrite
   * @par     category      = the category associated to the protocol
   *
   */
  void ndpi_set_proto_category(struct ndpi_detection_module_struct *ndpi_mod,
			       u_int16_t protoId, ndpi_protocol_category_t protoCategory);

  /**
   * Check if subprotocols of the specified master protocol are just
   * informative (and not real)
   *
   * @par     mod           = the detection module
   * @par     protoId       = the (master) protocol identifier to query
   * @return  1 = the subprotocol is informative, 0 otherwise.
   *
   */
  u_int8_t ndpi_is_subprotocol_informative(struct ndpi_detection_module_struct *ndpi_mod,
					   u_int16_t protoId);

  /**
   * Set hostname-based protocol
   *
   * @par ndpi_mod          = the detection module
   * @par flow              = the flow to which this communication belongs to
   * @par master_protocol   = the master protocol for this flow
   * @par name              = the host name
   * @par name_len          = length of the host name
   *
   */
  int ndpi_match_hostname_protocol(struct ndpi_detection_module_struct *ndpi_mod,
				   struct ndpi_flow_struct *flow,
				   u_int16_t master_protocol,				 
				   char *name, u_int name_len);

  /**
   * Get protocol category as string
   *
   * @par     mod           = the detection module
   * @par     category      = the category associated to the protocol
   * @return  the string name of the category
   *
   */
  const char* ndpi_category_get_name(struct ndpi_detection_module_struct *ndpi_mod,
				     ndpi_protocol_category_t category);

  /**
   * Set protocol category string
   *
   * @par     mod           = the detection module
   * @par     category      = the category associated to the protocol
   * @paw     name          = the string name of the category
   *
   */
  void ndpi_category_set_name(struct ndpi_detection_module_struct *ndpi_mod,
			      ndpi_protocol_category_t category, char *name);

  /**
   * Get protocol category
   *
   * @par     ndpi_mod      = the detection module
   * @par     proto         = the struct ndpi_protocol contain the protocols name
   * @return  the protocol category
   */
  ndpi_protocol_category_t ndpi_get_proto_category(struct ndpi_detection_module_struct *ndpi_mod,
						   ndpi_protocol proto);

  /**
   * Get the protocol name associated to the ID
   *
   * @par     mod           = the detection module
   * @par     proto_id      = the ID of the protocol
   * @return  the buffer contains the master_protocol and protocol name
   *
   */
  char* ndpi_get_proto_name(struct ndpi_detection_module_struct *mod, u_int16_t proto_id);


  /**
   * Return the protocol breed ID associated to the protocol
   *
   * @par     ndpi_struct   = the detection module
   * @par     proto         = the ID of the protocol
   * @return  the breed ID associated to the protocol
   *
   */
  ndpi_protocol_breed_t ndpi_get_proto_breed(struct ndpi_detection_module_struct *ndpi_struct,
					     u_int16_t proto);

  /**
   * Return the string name of the protocol breed
   *
   * @par     ndpi_struct   = the detection module
   * @par     breed_id      = the breed ID associated to the protocol
   * @return  the string name of the breed ID
   *
   */
  char* ndpi_get_proto_breed_name(struct ndpi_detection_module_struct *ndpi_struct,
				  ndpi_protocol_breed_t breed_id);

  /**
   * Return the ID of the protocol
   *
   * @par     ndpi_mod   = the detection module
   * @par     proto      = the protocol name
   * @return  the ID of the protocol
   *
   */
  int ndpi_get_protocol_id(struct ndpi_detection_module_struct *ndpi_mod, char *proto);

  /**
   * Return the ID of the category
   *
   * @par     ndpi_mod   = the detection module
   * @par     proto      = the category name
   * @return  the ID of the category
   *
   */
  int ndpi_get_category_id(struct ndpi_detection_module_struct *ndpi_mod, char *cat);

  /**
   * Write the list of the supported protocols
   *
   * @par  ndpi_mod = the detection module
   */
  void ndpi_dump_protocols(struct ndpi_detection_module_struct *mod);

  /**
   * Read a file and load the protocols
   *
   * Format: <tcp|udp>:<port>,<tcp|udp>:<port>,.....@<proto>
   *
   * Example:
   * tcp:80,tcp:3128@HTTP
   * udp:139@NETBIOS
   *
   * @par     ndpi_mod = the detection module
   * @par     path     = the path of the file
   * @return  0 if the file is loaded correctly;
   *          -1 else
   *
   */
  int ndpi_load_protocols_file(struct ndpi_detection_module_struct *ndpi_mod,
			       const char* path);

 /**
   * Read a file and load the categories
   *
   * @par     ndpi_mod = the detection module
   * @par     path     = the path of the file
   * @return  0 if the file is loaded correctly;
   *          -1 else
   */
  int ndpi_load_categories_file(struct ndpi_detection_module_struct *ndpi_str, const char* path);

  /**
   * Get the total number of the supported protocols
   *
   * @par     ndpi_mod = the detection module
   * @return  the number of protocols
   *
   */
  u_int ndpi_get_num_supported_protocols(struct ndpi_detection_module_struct *ndpi_mod);

  /**
   * Get the nDPI version release
   *
   * @return the NDPI_GIT_RELEASE
   *
   */
  char* ndpi_revision(void);

  /**
   * Set the automa for the protocol search
   *
   * @par ndpi_struct = the detection module
   * @par automa      = the automa to match
   *
   */
  void ndpi_set_automa(struct ndpi_detection_module_struct *ndpi_struct,
		       void* automa);

/* NDPI_PROTOCOL_HTTP */
  /**
   * Retrieve information for HTTP flows
   *
   * @par     ndpi_mod = the detection module
   * @par     flow     = the detected flow
   * @return  the HTTP method information about the flow
   *
  */
  ndpi_http_method ndpi_get_http_method(struct ndpi_detection_module_struct *ndpi_mod,
					struct ndpi_flow_struct *flow);

  /**
   * Get the HTTP url
   *
   * @par     ndpi_mod = the detection module
   * @par     flow     = the detected flow
   * @return  the HTTP method information about the flow
   *
  */
  char* ndpi_get_http_url(struct ndpi_detection_module_struct *ndpi_mod,
			  struct ndpi_flow_struct *flow);

  /**
   * Get the HTTP content-type
   *
   * @par     ndpi_mod = the detection module
   * @par     flow     = the detected flow
   * @return  the HTTP method information about the flow
   *
  */
  char* ndpi_get_http_content_type(struct ndpi_detection_module_struct *ndpi_mod,
				   struct ndpi_flow_struct *flow);

/* NDPI_PROTOCOL_TOR */
  /**
   * Check if the flow could be detected as TOR protocol
   *
   * @par     ndpi_struct = the detection module
   * @par     flow = the detected flow
   * @par     certificate = the SSL/TLS certificate
   * @return  1 if the flow is TOR;
   *          0 else
   *
   */
  int ndpi_is_tls_tor(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow, char *certificate);

  /* Wrappers functions */
  /**
   * Init Aho-Corasick automata
   *
   * @return  The requested automata, or NULL if an error occurred
   *
   */
  void* ndpi_init_automa(void);

  /**
   * Free Aho-Corasick automata allocated with ndpi_init_automa();
   *
   * @par     The automata initialized with ndpi_init_automa();
   *
   */
  void ndpi_free_automa(void *_automa);

  /**
   * Add a string to match to an automata
   *
   * @par     The automata initialized with ndpi_init_automa();
   * @par     The (sub)string to search
   * @par     The number associated with this string
   * @return  0 in case of no error, or -1 if an error occurred.
   *
   */
  int ndpi_add_string_value_to_automa(void *_automa, char *str, unsigned long num);

  /**
   * Add a string to match to an automata. Same as ndpi_add_string_value_to_automa() with num set to 1
   *
   * @par     The automata initialized with ndpi_init_automa();
   * @par     The (sub)string to search
   * @return  0 in case of no error, or -1 if an error occurred.
   *
   */
  int ndpi_add_string_to_automa(void *_automa, char *str);

  /**
   * Finalize the automa (necessary before start searching)
   *
   * @par     The automata initialized with ndpi_init_automa();
   *
   */
  void ndpi_finalize_automa(void *_automa);

  /**
   * Add a string to match to an automata
   *
   * @par     The automata initialized with ndpi_init_automa();
   * @par     The (sub)string to search
   * @return  0 in case of match, or -1 if no match, or -2 if an error occurred.
   *
   */
  int ndpi_match_string(void *_automa, char *string_to_match);

  int ndpi_load_ip_category(struct ndpi_detection_module_struct *ndpi_struct,
				 const char *ip_address_and_mask, ndpi_protocol_category_t category);
  int ndpi_load_hostname_category(struct ndpi_detection_module_struct *ndpi_struct,
				 const char *name_to_add, ndpi_protocol_category_t category);
  int ndpi_load_category(struct ndpi_detection_module_struct *ndpi_struct,
				 const char *ip_or_name, ndpi_protocol_category_t category);
  int ndpi_enable_loaded_categories(struct ndpi_detection_module_struct *ndpi_struct);
  int ndpi_fill_ip_protocol_category(struct ndpi_detection_module_struct *ndpi_struct,
				 u_int32_t saddr,
				 u_int32_t daddr,
				 ndpi_protocol *ret);
  int ndpi_match_custom_category(struct ndpi_detection_module_struct *ndpi_struct,
				 char *name, u_int name_len, unsigned long *id);
  void ndpi_fill_protocol_category(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow,
				   ndpi_protocol *ret);
  int ndpi_get_custom_category_match(struct ndpi_detection_module_struct *ndpi_struct,
				     char *name_or_ip, u_int name_len, unsigned long *id);
  int ndpi_set_detection_preferences(struct ndpi_detection_module_struct *ndpi_mod,
				     ndpi_detection_preference pref,
				     int value);

  /* Tells to called on what l4 protocol given application protocol can be found */
  ndpi_l4_proto_info ndpi_get_l4_proto_info(struct ndpi_detection_module_struct *ndpi_struct, u_int16_t ndpi_proto_id);
  const char* ndpi_get_l4_proto_name(ndpi_l4_proto_info proto);
    
  ndpi_proto_defaults_t* ndpi_get_proto_defaults(struct ndpi_detection_module_struct *ndpi_mod);
  u_int ndpi_get_ndpi_num_supported_protocols(struct ndpi_detection_module_struct *ndpi_mod);
  u_int ndpi_get_ndpi_num_custom_protocols(struct ndpi_detection_module_struct *ndpi_mod);
  u_int ndpi_get_ndpi_detection_module_size(void);
  void ndpi_set_log_level(struct ndpi_detection_module_struct *ndpi_mod, u_int l);

  /* LRU cache */
  struct ndpi_lru_cache* ndpi_lru_cache_init(u_int32_t num_entries);
  void ndpi_lru_free_cache(struct ndpi_lru_cache *c);
  u_int8_t ndpi_lru_find_cache(struct ndpi_lru_cache *c, u_int32_t key,
			       u_int16_t *value, u_int8_t clean_key_when_found);
  void ndpi_lru_add_to_cache(struct ndpi_lru_cache *c, u_int32_t key, u_int16_t value);
  
  /**
   * Add a string to match to an automata
   *
   * @par     The automata initialized with ndpi_init_automa();
   * @par     The (sub)string to search
   * @par     The (sub)string length
   * @par     The id associated with the matched string or 0 id not found.
   * @return  0 in case of match, or -1 if no match, or -2 if an error occurred.
   *
   */
  int ndpi_match_string_id(void *_automa, char *string_to_match, u_int match_len, unsigned long *id);

  /* Utility functions to set ndpi malloc/free/print wrappers */
  void set_ndpi_malloc(void* (*__ndpi_malloc)(size_t size));
  void set_ndpi_free(void  (*__ndpi_free)(void *ptr));
  void set_ndpi_flow_malloc(void* (*__ndpi_flow_malloc)(size_t size));
  void set_ndpi_flow_free(void  (*__ndpi_flow_free)(void *ptr));
  void set_ndpi_debug_function(struct ndpi_detection_module_struct *ndpi_str,
			       ndpi_debug_function_ptr ndpi_debug_printf);
  //void * ndpi_malloc(size_t size);
  //void * ndpi_calloc(unsigned long count, size_t size);
  //void ndpi_free(void *ptr);
  u_int8_t ndpi_get_api_version(void);

  /* https://github.com/corelight/community-id-spec */
  int ndpi_flowv4_flow_hash(u_int8_t l4_proto, u_int32_t src_ip, u_int32_t dst_ip, u_int16_t src_port, u_int16_t dst_port,
			    u_int8_t icmp_type, u_int8_t icmp_code, u_char *hash_buf, u_int8_t hash_buf_len);
  int ndpi_flowv6_flow_hash(u_int8_t l4_proto, struct ndpi_in6_addr *src_ip, struct ndpi_in6_addr *dst_ip,
			    u_int16_t src_port, u_int16_t dst_port, u_int8_t icmp_type, u_int8_t icmp_code,
			    u_char *hash_buf, u_int8_t hash_buf_len);
  u_int8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *ndpi_struct,
					  struct ndpi_flow_struct *flow);    
  u_int8_t ndpi_is_safe_ssl_cipher(u_int32_t cipher);
  const char* ndpi_cipher2str(u_int32_t cipher);
  const char* ndpi_tunnel2str(ndpi_packet_tunnel tt);
  u_int16_t ndpi_guess_host_protocol_id(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow);
  int ndpi_has_human_readeable_string(struct ndpi_detection_module_struct *ndpi_struct,
				      char *buffer, u_int buffer_size,
				      u_int8_t min_string_match_len, /* Will return 0 if no string > min_string_match_len have been found */
				      char *outbuf, u_int outbuf_len);
  char* ndpi_ssl_version2str(u_int16_t version, u_int8_t *unknown_tls_version);
  void ndpi_patchIPv6Address(char *str);
  void ndpi_user_pwd_payload_copy(u_int8_t *dest, u_int dest_len, u_int offset,
				  const u_int8_t *src, u_int src_len);
  u_char* ndpi_base64_decode(const u_char *src, size_t len, size_t *out_len);
  char* ndpi_base64_encode(unsigned char const* bytes_to_encode, ssize_t in_len);
  int ndpi_load_ipv4_ptree(struct ndpi_detection_module_struct *ndpi_str,
			   const char *path, u_int16_t protocol_id);
    
  int ndpi_flow2json(struct ndpi_detection_module_struct *ndpi_struct,
		     struct ndpi_flow_struct *flow,
		     u_int8_t ip_version,
		     u_int8_t l4_protocol, u_int16_t vlan_id,
		     u_int32_t src_v4, u_int32_t dst_v4,
		     struct ndpi_in6_addr *src_v6, struct ndpi_in6_addr *dst_v6,
		     u_int16_t src_port, u_int16_t dst_port,
		     ndpi_protocol l7_protocol,
		     ndpi_serializer *serializer);

  void ndpi_md5(const u_char *data, size_t data_len, u_char hash[16]);

  /* ptree (trie) API */
  ndpi_ptree_t* ndpi_ptree_create(void);
  int ndpi_ptree_insert(ndpi_ptree_t *tree, const ndpi_ip_addr_t *addr, u_int8_t bits, uint user_data);
  int ndpi_ptree_match_addr(ndpi_ptree_t *tree, const ndpi_ip_addr_t *addr, uint *user_data);
  void ndpi_ptree_destroy(ndpi_ptree_t *tree);

  /* Serializer */
  int ndpi_init_serializer_ll(ndpi_serializer *serializer, ndpi_serialization_format fmt,
			      u_int32_t buffer_size);
  int ndpi_init_serializer(ndpi_serializer *serializer, ndpi_serialization_format fmt);
  void ndpi_term_serializer(ndpi_serializer *serializer);
  void ndpi_reset_serializer(ndpi_serializer *serializer);

  int ndpi_serialize_uint32_uint32(ndpi_serializer *serializer,
				   u_int32_t key, u_int32_t value);
  int ndpi_serialize_uint32_uint64(ndpi_serializer *serializer,
				   u_int32_t key, u_int64_t value);
  int ndpi_serialize_uint32_int32(ndpi_serializer *serializer,
				  u_int32_t key, int32_t value);
  int ndpi_serialize_uint32_int64(ndpi_serializer *serializer,
				  u_int32_t key, int64_t value);
  int ndpi_serialize_uint32_float(ndpi_serializer *serializer,
				  u_int32_t key, float value,
				  const char *format /* e.f. "%.2f" */);
  int ndpi_serialize_uint32_string(ndpi_serializer *serializer,
				   u_int32_t key, const char *value);
  int ndpi_serialize_uint32_boolean(ndpi_serializer *serializer,
				    u_int32_t key, u_int8_t value);

  int ndpi_serialize_string_int32(ndpi_serializer *serializer,
				  const char *key, int32_t value);
  int ndpi_serialize_string_int64(ndpi_serializer *serializer,
				  const char *key, int64_t value);  
  int ndpi_serialize_string_uint32(ndpi_serializer *serializer,
				   const char *key, u_int32_t value);
  int ndpi_serialize_string_uint32_format(ndpi_serializer *serializer,
					  const char *key, u_int32_t value,
					  const char *format);
  int ndpi_serialize_string_uint64(ndpi_serializer *serializer,
				   const char *key, u_int64_t value);
  int ndpi_serialize_string_string(ndpi_serializer *serializer,
				   const char *key, const char *value);
  int ndpi_serialize_string_binary(ndpi_serializer *serializer,
				   const char *key, const char *_value,
				   u_int16_t vlen);
  int ndpi_serialize_string_raw(ndpi_serializer *_serializer,
				const char *key, const char *_value,
                                u_int16_t vlen);
  int ndpi_serialize_string_float(ndpi_serializer *serializer,
				  const char *key, float value,
				  const char *format /* e.f. "%.2f" */);
  int ndpi_serialize_string_boolean(ndpi_serializer *serializer,
				    const char *key, u_int8_t value);

  int ndpi_serialize_end_of_record(ndpi_serializer *serializer);
  int ndpi_serialize_start_of_block(ndpi_serializer *serializer,
				    const char *key);
  int ndpi_serialize_end_of_block(ndpi_serializer *serializer);
  char* ndpi_serializer_get_buffer(ndpi_serializer *serializer, u_int32_t *buffer_len);
  u_int32_t ndpi_serializer_get_buffer_len(ndpi_serializer *serializer);
  u_int32_t ndpi_serializer_get_internal_buffer_size(ndpi_serializer *serializer);
  int ndpi_serializer_set_buffer_len(ndpi_serializer *serializer, u_int32_t l);
  void ndpi_serializer_set_csv_separator(ndpi_serializer *serializer, char separator);

  void ndpi_serializer_create_snapshot(ndpi_serializer *serializer);
  void ndpi_serializer_rollback_snapshot(ndpi_serializer *serializer);
  
  /* Deserializer */
  int ndpi_init_deserializer(ndpi_deserializer *deserializer,
			     ndpi_serializer *serializer);
  int ndpi_init_deserializer_buf(ndpi_deserializer *deserializer,
				 u_int8_t *serialized_buffer,
				 u_int32_t serialized_buffer_len);
  
  ndpi_serialization_format ndpi_deserialize_get_format(ndpi_deserializer *_deserializer);
  ndpi_serialization_type ndpi_deserialize_get_item_type(ndpi_deserializer *deserializer, ndpi_serialization_type *key_type);
  int ndpi_deserialize_next(ndpi_deserializer *deserializer);

  int ndpi_deserialize_key_uint32(ndpi_deserializer *deserializer, u_int32_t *key);
  int ndpi_deserialize_key_string(ndpi_deserializer *deserializer, ndpi_string *key);

  int ndpi_deserialize_value_uint32(ndpi_deserializer *deserializer, u_int32_t *value);
  int ndpi_deserialize_value_uint64(ndpi_deserializer *deserializer, u_int64_t *value);
  int ndpi_deserialize_value_int32(ndpi_deserializer *deserializer, int32_t *value);
  int ndpi_deserialize_value_int64(ndpi_deserializer *deserializer, int64_t *value);
  int ndpi_deserialize_value_float(ndpi_deserializer *deserializer, float *value);
  int ndpi_deserialize_value_string(ndpi_deserializer *deserializer, ndpi_string *value);

  int ndpi_deserialize_clone_item(ndpi_deserializer *deserializer, ndpi_serializer *serializer);
  int ndpi_deserialize_clone_all(ndpi_deserializer *deserializer, ndpi_serializer *serializer);

  /* Data analysis */
  struct ndpi_analyze_struct* ndpi_alloc_data_analysis(u_int16_t _max_series_len);
  void ndpi_init_data_analysis(struct ndpi_analyze_struct *s, u_int16_t _max_series_len);
  void ndpi_free_data_analysis(struct ndpi_analyze_struct *d);
  void ndpi_data_add_value(struct ndpi_analyze_struct *s, const u_int32_t value);

  float ndpi_data_average(struct ndpi_analyze_struct *s);
  float ndpi_data_window_average(struct ndpi_analyze_struct *s);
  
  float ndpi_data_entropy(struct ndpi_analyze_struct *s);
  float ndpi_data_variance(struct ndpi_analyze_struct *s);
  float ndpi_data_stddev(struct ndpi_analyze_struct *s);
  u_int32_t ndpi_data_min(struct ndpi_analyze_struct *s);
  u_int32_t ndpi_data_max(struct ndpi_analyze_struct *s);
  float ndpi_data_ratio(u_int32_t sent, u_int32_t rcvd);
    
  const char* ndpi_data_ratio2str(float ratio);
  
  void ndpi_data_print_window_values(struct ndpi_analyze_struct *s); /* debug */

  ndpi_url_risk ndpi_validate_url(char *url);

  u_int8_t ndpi_is_protocol_detected(struct ndpi_detection_module_struct *ndpi_str,
				     ndpi_protocol proto);
#ifdef __cplusplus
}
#endif

#endif	/* __NDPI_API_H__ */
