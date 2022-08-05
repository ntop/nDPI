/*
 * softether.c
 *
 * Copyright (C) 2022 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SOFTETHER

#include "ndpi_api.h"

enum softether_value_type {
  VALUE_INT    = 0u,
  VALUE_DATA   = 1u,
  VALUE_STR    = 2u,
  VALUE_UNISTR = 3u,
  VALUE_INT64  = 4u
};

union softether_dissected_value {
  int value_int;
  u_int64_t value_int64;
  union {
    void const *raw;
    u_int8_t const *value_data;
    char const *value_str;
    char const *value_unistr;
  } ptr;
};

struct softether_value {
  enum softether_value_type type;
  union softether_dissected_value value;
  u_int32_t value_size;
};

static int ndpi_search_softether_again(struct ndpi_detection_module_struct *ndpi_struct,
                                       struct ndpi_flow_struct *flow);

/* ***************************************************** */

static void ndpi_int_softether_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
					      struct ndpi_flow_struct * const flow) {
  NDPI_LOG_INFO(ndpi_struct, "found softether\n");

  flow->check_extra_packets = 1;
  flow->max_extra_packets_to_check = 15;
  flow->extra_packets_func = ndpi_search_softether_again;

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_SOFTETHER,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ***************************************************** */

static size_t dissect_softether_type(enum softether_value_type t,
                                     struct softether_value *v,
                                     u_int8_t const *payload,
                                     u_int16_t payload_len) {
  size_t ret = 0;
  v->type = t;
  v->value_size = 0;

  switch (t)
    {
    case VALUE_INT:
      if(payload_len < 4)
	return 0;

      v->value.value_int = ntohl(get_u_int32_t(payload, 0));
      v->value_size = sizeof(v->value.value_int);
      ret = v->value_size;
      break;

    case VALUE_DATA:
    case VALUE_STR:
    case VALUE_UNISTR:
      if(payload_len < 4)
	return 0;

      v->value.ptr.raw = payload + 4;
      u_int32_t siz = ntohl(get_u_int32_t(payload, 0));
      if(payload_len < siz + 3)
	return 0;

      if(t == VALUE_DATA)
	siz--;

      v->value_size = siz;
      ret = siz + sizeof(siz);
      break;

    case VALUE_INT64:
      if(payload_len < 8)
	return 0;

      v->value.value_int64 = ndpi_ntohll(get_u_int64_t(payload, 0));
      v->value_size = sizeof(v->value.value_int64);
      ret = v->value_size;
      break;
    }

  if(ret > payload_len)
    return 0;

  return ret;
}

/* ***************************************************** */

static int softether_type_to_enum(u_int32_t type, enum softether_value_type *result) {
  switch (type)
    {
    case VALUE_INT:
    case VALUE_DATA:
    case VALUE_STR:
    case VALUE_UNISTR:
    case VALUE_INT64:
      *result = (enum softether_value_type)type;
      return 0;
    }

  return 1;
}

/* ***************************************************** */

static size_t dissect_softether_tuples(u_int8_t const *payload, u_int16_t payload_len,
                                       struct softether_value *first_value,
                                       struct softether_value *second_value) {
  enum softether_value_type first_tuple_type;
  enum softether_value_type second_tuple_type;
  size_t value_siz;
  size_t const tuple_type_len = 8;

  if(payload_len < tuple_type_len)
    return 0;

  if(softether_type_to_enum(ntohl(get_u_int32_t(payload, 0)), &first_tuple_type) != 0 ||
     softether_type_to_enum(ntohl(get_u_int32_t(payload, 4)), &second_tuple_type) != 0)
    return 0;

  payload += tuple_type_len;
  payload_len -= tuple_type_len;

  value_siz = dissect_softether_type(first_tuple_type, first_value, payload, payload_len);

  payload += value_siz;
  payload_len -= value_siz;

  value_siz += dissect_softether_type(second_tuple_type, second_value, payload, payload_len);

  return value_siz + tuple_type_len;
}

/* ***************************************************** */

static int dissect_softether_host_fqdn(struct ndpi_flow_struct *flow,
                                       struct ndpi_packet_struct const *packet) {
  u_int8_t const *payload = packet->payload;
  u_int16_t payload_len = packet->payload_packet_len;
  u_int32_t tuple_count;
  size_t value_siz;
  struct softether_value val1, val2;
  uint8_t got_hostname = 0, got_fqdn = 0;

  if(payload_len < 4)
    return 1;

  tuple_count = ntohl(get_u_int32_t(payload, 0));
  if(tuple_count == 0 || tuple_count * 8 > payload_len)
    return 1;

  payload += 4;
  payload_len -= 4;

  value_siz = dissect_softether_type(VALUE_DATA, &val1, payload, payload_len);
  if(value_siz == 0)
    return 1;

  payload += value_siz;
  payload_len -= value_siz;

  if(strncmp(val1.value.ptr.value_str, "host_name", value_siz) == 0)
    got_hostname = 1;

  for (; tuple_count > 0; --tuple_count) {
    value_siz = dissect_softether_tuples(payload, payload_len, &val1, &val2);
    if(value_siz == 0)
      break;

    if(got_hostname == 1) {
      if(val1.type == VALUE_STR && val1.value_size > 0) {
	size_t len = ndpi_min(val1.value_size, sizeof(flow->protos.softether.hostname) - 1);
	      
	strncpy(flow->protos.softether.hostname, val1.value.ptr.value_str, len);
	flow->protos.softether.hostname[len] = '\0';
      }
	  
      got_hostname = 0;
    }
    if(got_fqdn == 1) {
      if(val1.type == VALUE_STR && val1.value_size > 0)  {
	size_t len = ndpi_min(val1.value_size, sizeof(flow->protos.softether.fqdn) - 1);
	      
	strncpy(flow->protos.softether.fqdn, val1.value.ptr.value_str, len);
	flow->protos.softether.fqdn[len] = '\0';
      }
	  
      got_fqdn = 0;
    }

    if(val2.type == VALUE_DATA && val2.value_size > 0 &&
       strncmp(val2.value.ptr.value_str, "ddns_fqdn", val2.value_size) == 0)	{
      got_fqdn = 1;
    }

    payload += value_siz;
    payload_len -= value_siz;
  }

  if(payload_len != 0 || tuple_count != 0)
    return 1;

  return 0;
}

/* ***************************************************** */

static int dissect_softether_ip_port(struct ndpi_flow_struct *flow,
                                     struct ndpi_packet_struct const *packet) {
  char * ip_port_separator;
  size_t ip_len, port_len;

  if(packet->payload_packet_len < NDPI_STATICSTRING_LEN("IP=") +
     NDPI_STATICSTRING_LEN(",PORT="))
    return 1;    

  if(strncmp((char *)&packet->payload[0], "IP=", NDPI_STATICSTRING_LEN("IP=")) != 0)    
    return 1;    

  ip_port_separator = ndpi_strnstr((char const *)packet->payload + NDPI_STATICSTRING_LEN("IP="),
                                   ",PORT=",
                                   packet->payload_packet_len - NDPI_STATICSTRING_LEN("IP="));
  if(ip_port_separator == NULL)    
    return 1;    

  if(ip_port_separator < (char const *)packet->payload + NDPI_STATICSTRING_LEN("IP="))    
    return 1;    

  ip_len = ndpi_min(sizeof(flow->protos.softether.ip) - 1,
                    ip_port_separator - (char const *)packet->payload -
                    NDPI_STATICSTRING_LEN("IP="));

  strncpy(flow->protos.softether.ip,
	  (char const *)packet->payload + NDPI_STATICSTRING_LEN("IP="),
          ip_len);
  flow->protos.softether.ip[ip_len] = '\0';

  if(ip_port_separator < (char const *)packet->payload +
     NDPI_STATICSTRING_LEN("IP=") + NDPI_STATICSTRING_LEN(",PORT="))
    return 1;    

  port_len = ndpi_min(sizeof(flow->protos.softether.port) - 1,
                      ip_port_separator - (char const *)packet->payload -
                      NDPI_STATICSTRING_LEN("IP=") - NDPI_STATICSTRING_LEN(",PORT="));

  strncpy(flow->protos.softether.port,
	  ip_port_separator + NDPI_STATICSTRING_LEN(",PORT="),
          port_len);
  
  flow->protos.softether.port[port_len] = '\0';

  return 0;
}

/* ***************************************************** */

void ndpi_search_softether(struct ndpi_detection_module_struct *ndpi_struct,
                           struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search softether\n");

  if(packet->payload_packet_len == 1) {

    if((packet->payload[0] != 0x41) || (flow->packet_counter > 2))	
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);	

    return;
  }

  if(packet->payload_packet_len > 9 && packet->payload_packet_len < 30) {
    if(dissect_softether_ip_port(flow, packet) == 0) {
      ndpi_int_softether_add_connection(ndpi_struct, flow);
      return;
    }
  }
    
  if(packet->payload_packet_len >= 99) {
    if(dissect_softether_host_fqdn(flow, packet) == 0) {
      ndpi_int_softether_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ***************************************************** */
  
static int ndpi_search_softether_again(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow) {
  if((dissect_softether_ip_port(flow, &ndpi_struct->packet) == 0)
     || (dissect_softether_host_fqdn(flow, &ndpi_struct->packet) == 0)) {
    if((flow->protos.softether.ip[0] != '\0')
       && (flow->protos.softether.port[0] != '\0')
       && (flow->protos.softether.hostname[0] != '\0')
       && (flow->protos.softether.fqdn[0] != '\0')) {
      flow->check_extra_packets = 0;
      flow->max_extra_packets_to_check = 0;
      flow->extra_packets_func = NULL;

      return 0;
    }
  }

  return 1;
}

/* ***************************************************** */
  
void init_softether_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			      u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("Softether", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SOFTETHER,
				      ndpi_search_softether,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK
				      );

  *id += 1;
}
