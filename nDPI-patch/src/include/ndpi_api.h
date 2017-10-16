/*
 * ndpi_api.h
 *
 * Copyright (C) 2011-16 - ntop.org
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
 * Rev.1.1
 *
 */


#ifndef __NDPI_API_H__
#define __NDPI_API_H__

#include "ndpi_main.h"

#ifdef __cplusplus
extern "C" {
#endif

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
  int check_punycode_string(char * buff , int len);

  
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
   * Returns the nDPI protocol id for IP-based protocol detection
   *
   * @par    ndpi_struct  = the struct created for the protocol detection
   * @par    pin          = IP host address (MUST BE in network byte order):
   *                        See man(7) ip for details
   * @return the nDPI protocol ID
   * 
   */
  u_int16_t ndpi_network_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, struct in_addr *pin);


  /**
   * Init single protocol match
   *
   * @par ndpi_mod  = the struct created for the protocol detection
   * @par match     = the struct passed to match the protocol
   *
   */  
  void ndpi_init_protocol_match(struct ndpi_detection_module_struct *ndpi_mod, ndpi_protocol_match *match);
  
  /**
   * Returns a new initialized detection module
   *
   * @return  the initialized detection module
   *
   */
  struct ndpi_detection_module_struct *ndpi_init_detection_module(void);
  
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
  void ndpi_enable_cache(struct ndpi_detection_module_struct *ndpi_mod, char* host, u_int port);

  
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
  void ndpi_set_bitmask_protocol_detection(char *label, struct ndpi_detection_module_struct *ndpi_struct,
					   const NDPI_PROTOCOL_BITMASK *detection_bitmask,
					   const u_int32_t idx,
					   u_int16_t ndpi_protocol_id,
					   void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow),
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
   * @return the detected protocol even if the flow is not completed;
   *         
   */
  ndpi_protocol ndpi_detection_giveup(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow);

  
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
   * Processes one packet of L4 and returns the ID of the detected protocol.
   * L3 and L4 packet headers are passed in the arguments while payload
   * points to the L4 body.
   * This function mimics ndpi_detection_process_packet behaviour.
   *
   * @par    ndpi_struct           = the detection module
   * @par    flow                  = pointer to the connection state machine
   * @par    iph                   = IP packet header for IPv4 or NULL
   * @par    iph6                  = IP packet header for IPv6 or NULL
   * @par    tcp                   = TCP packet header for TCP or NULL
   * @par    udp                   = UDP packet header for UDP or NULL
   * @par    src_to_dst_direction  = order of src/dst state machines in a flow.
   * @par    l4_proto              = L4 protocol of the packet.
   * @par    src                   = pointer to the source subscriber state machine
   * @par    dst                   = pointer to the destination subscriber state machine
   * @par    sport                 = source port of L4 packet, used for protocol guessing.
   * @par    dport                 = destination port of L4 packet, used for protocol guessing.
   * @par    current_tick_l        = the current timestamp for the packet
   * @par    payload               = unsigned char pointer to the Layer 4 (TCP/UDP body)
   * @par    payload_len           = the length of the payload
   * @return the detected ID of the protocol
   *
   * NOTE: in a current implementation flow->src and flow->dst are swapped with
   * the src_to_dst_direction flag while ndpi_detection_process_packet does not swap
   * these values.
   *
   */

ndpi_protocol ndpi_l4_detection_process_packet(struct ndpi_detection_module_struct *ndpi_struct,
					       struct ndpi_flow_struct *flow,
					       const struct ndpi_iphdr *iph,
					       struct ndpi_ipv6hdr *iph6,
					       struct ndpi_tcphdr *tcp,
					       struct ndpi_udphdr *udp,
					       u_int8_t src_to_dst_direction,
					       u_int8_t l4_proto,
					       struct ndpi_id_struct *src,
					       u_int16_t sport,
					       struct ndpi_id_struct *dst,
					       u_int16_t dport,
					       const u_int64_t current_tick_l,
					       u_int8_t *payload, u_int16_t payload_len);


  
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


#if 0
  /**
   * returns true if the protocol history of the flow of the last packet given to the detection
   * contains the given protocol.
   *
   * @param ndpi_struct the detection module
   * @return 1 if protocol has been found, 0 otherwise
   *
   */
  u_int8_t ndpi_detection_flow_protocol_history_contains_protocol(struct ndpi_detection_module_struct *ndpi_struct,
  								  struct ndpi_flow_struct *flow,
  								  u_int16_t protocol_id);
#endif

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
   * @par    proto        = the l4 protocol number
   * @par    shost        = source address in host byte order
   * @par    sport        = source port number
   * @par    dhost        = destination address in host byte order
   * @par    dport        = destination port number
   * @return the struct ndpi_protocol that match the port base protocol 
   *
   */
  ndpi_protocol ndpi_guess_undetected_protocol(struct ndpi_detection_module_struct *ndpi_struct,
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
   * @par    is_host_match       = value of the second field of struct ndpi_automa
   * @return the ID of the matched subprotocol
   *
   */
  int ndpi_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				    char *string_to_match,
				    u_int string_to_match_len,
				    u_int8_t is_host_match);


  /**
   * Check if the host passed match with a protocol
   * 
   * @par    ndpi_struct         = the detection module
   * @par    flow                = the flow where match the host
   * @par    string_to_match     = the string to match
   * @par    string_to_match_len = the length of the string
   * @par    master_protocol_id  = value of the ID associated to the master protocol detected
   * @return the ID of the matched subprotocol
   *
   */
  int ndpi_match_host_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  char *string_to_match,
				  u_int string_to_match_len,
				  u_int16_t master_protocol_id);


  /**
   * Check if the string content passed match with a protocol
   * 
   * @par    ndpi_struct         = the detection module
   * @par    flow                = the flow where match the host
   * @par    string_to_match     = the string to match
   * @par    string_to_match_len = the length of the string
   * @par    master_protocol_id  = value of the ID associated to the master protocol detected
   * @return the ID of the matched subprotocol
   *
   */
  int ndpi_match_content_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow,
				     char *string_to_match,
				     u_int string_to_match_len,
				     u_int16_t master_protocol_id);

  
  /**
   * Check if the string -bigram_to_match- match with a bigram of -automa-
   *
   * @par     ndpi_struct      = the detection module
   * @par     automa           = the struct ndpi_automa for the bigram
   * @par     bigram_to_match  = the bigram string to match
   * @return  0
   *
   */
  int ndpi_match_bigram(struct ndpi_detection_module_struct *ndpi_struct, 
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
  char* ndpi_protocol2name(struct ndpi_detection_module_struct *ndpi_mod, ndpi_protocol proto, char *buf, u_int buf_len);

  
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
  ndpi_protocol_breed_t ndpi_get_proto_breed(struct ndpi_detection_module_struct *ndpi_struct, u_int16_t proto);

  
  /**
   * Return the string name of the protocol breed
   *
   * @par     ndpi_struct   = the detection module
   * @par     breed_id      = the breed ID associated to the protocol
   * @return  the string name of the breed ID     
   *
   */
  char* ndpi_get_proto_breed_name(struct ndpi_detection_module_struct *ndpi_struct, ndpi_protocol_breed_t breed_id);


  /**
   * Return the ID of the protocol
   *
   * @par     ndpi_mod   = the detection module
   * @par     proto      = the ID of the protocol
   * @return  the string name of the breed ID     
   *
   */
  int ndpi_get_protocol_id(struct ndpi_detection_module_struct *ndpi_mod, char *proto);


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
  int ndpi_load_protocols_file(struct ndpi_detection_module_struct *ndpi_mod, char* path);


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
  void ndpi_set_automa(struct ndpi_detection_module_struct *ndpi_struct, void* automa);


#ifdef NDPI_PROTOCOL_HTTP
  /**
   * Retrieve information for HTTP flows
   *
   * @par     ndpi_mod = the detection module
   * @par     flow     = the detected flow
   * @return  the HTTP method information about the flow
   *
  */
  ndpi_http_method ndpi_get_http_method(struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *flow);

  
  /**
   * Get the HTTP url
   *
   * @par     ndpi_mod = the detection module
   * @par     flow     = the detected flow
   * @return  the HTTP method information about the flow
   *
  */
  char* ndpi_get_http_url(struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *flow);


  /**
   * Get the HTTP content-type
   *
   * @par     ndpi_mod = the detection module
   * @par     flow     = the detected flow
   * @return  the HTTP method information about the flow
   *
  */
  char* ndpi_get_http_content_type(struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *flow);
#endif

  
#ifdef NDPI_PROTOCOL_TOR
  /**
   * Check if the flow could be detected as TOR protocol
   *
   * @par     ndpi_struct = the detection module
   * @par     flow = the detected flow
   * @par     certificate = the ssl certificate
   * @return  1 if the flow is TOR;
   *          0 else
   * 
   */
  int ndpi_is_ssl_tor(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow, char *certificate);
#endif

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


  /* Utility functions to set ndpi malloc/free/print wrappers */
  void set_ndpi_malloc(void* (*__ndpi_malloc)(size_t size));
  void set_ndpi_free(void  (*__ndpi_free)(void *ptr));
  void set_ndpi_debug_function(ndpi_debug_function_ptr ndpi_debug_printf);

#ifdef __cplusplus
}
#endif

#endif	/* __NDPI_API_H__ */
