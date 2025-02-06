/*
 * fastcgi.c
 *
 * Copyright (C) 2022-23 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FASTCGI

#include "ndpi_api.h"
#include "ndpi_private.h"

/* Reference: http://www.mit.edu/~yandros/doc/specs/fcgi-spec.html */

PACK_ON
struct FCGI_Header {
  u_int8_t version;
  u_int8_t type;
  u_int16_t requestId;
  u_int16_t contentLength;
  u_int8_t paddingLength;
  u_int8_t reserved;
} PACK_OFF;

enum FCGI_Type {
  FCGI_MIN                = 1,

  FCGI_BEGIN_REQUEST      = 1,
  FCGI_ABORT_REQUEST      = 2,
  FCGI_END_REQUEST        = 3,
  FCGI_PARAMS             = 4,
  FCGI_STDIN              = 5,
  FCGI_STDOUT             = 6,
  FCGI_STDERR             = 7,
  FCGI_DATA               = 8,
  FCGI_GET_VALUES         = 9,
  FCGI_GET_VALUES_RESULT  = 10,
  FCGI_UNKNOWN_TYPE       = 11,

  FCGI_MAX                = 11
};

PACK_ON
struct FCGI_Params {
  u_int8_t key_length;
  u_int8_t value_length;
} PACK_OFF;

struct fcgi_one_line_mapping {
  char const * const key;
  struct ndpi_int_one_line_struct * const value;
};

static int ndpi_search_fastcgi_extra(struct ndpi_detection_module_struct *ndpi_struct,
                                     struct ndpi_flow_struct *flow);

static void ndpi_int_fastcgi_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                            struct ndpi_flow_struct * const flow,
                                            ndpi_protocol_match_result * const match)
{
  NDPI_LOG_INFO(ndpi_struct, "found fastcgi\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_FASTCGI,
                             (match != NULL ? match->protocol_id : NDPI_PROTOCOL_UNKNOWN),
                             NDPI_CONFIDENCE_DPI);

  if (flow->extra_packets_func == NULL)
  {
    flow->max_extra_packets_to_check = 5;
    flow->extra_packets_func = ndpi_search_fastcgi_extra;
  }
}

static int fcgi_parse_params(struct ndpi_flow_struct * const flow,
                             struct ndpi_packet_struct * const packet)
{
  size_t i, j;
  struct fcgi_one_line_mapping mappings[] = {
    { "SCRIPT_URL", &packet->http_url_name },
    { "HTTP_HOST", &packet->host_line },
    { "HTTP_ACCEPT", &packet->accept_line },
    { "HTTP_USER_AGENT", &packet->user_agent_line },
    { "SERVER_SOFTWARE", &packet->server_line },
    { "REQUEST_METHOD", &packet->http_method }
  };

  i = sizeof(struct FCGI_Header);
  while (i + sizeof(struct FCGI_Params) < packet->payload_packet_len)
  {
    struct FCGI_Params const * const params = (struct FCGI_Params const *)&packet->payload[i];

    i += sizeof(*params);
    if (i + params->key_length + params->value_length > packet->payload_packet_len)
    {
      return 1;
    }

    for (j = 0; j < NDPI_ARRAY_LENGTH(mappings); ++j)
    {
      if (strlen(mappings[j].key) == params->key_length &&
          strncmp((char const *)&packet->payload[i], mappings[j].key, params->key_length) == 0)
      {
        mappings[j].value->ptr = &packet->payload[i + params->key_length];
        mappings[j].value->len = params->value_length;
        if (packet->parsed_lines < NDPI_MAX_PARSE_LINES_PER_PACKET)
        {
          packet->line[packet->parsed_lines].ptr = &packet->payload[i + params->key_length];
          packet->line[packet->parsed_lines].len = params->value_length;
          packet->parsed_lines++;
        }
        break;
      }
    }

    i += params->key_length + params->value_length;
  };

  if (i != packet->payload_packet_len)
  {
    return 1;
  }

  flow->http.method = ndpi_http_str2method((const char*)packet->http_method.ptr,
                                           (u_int16_t)packet->http_method.len);
  ndpi_hostname_sni_set(flow, packet->host_line.ptr, packet->host_line.len, NDPI_HOSTNAME_NORM_ALL);
  ndpi_user_agent_set(flow, packet->user_agent_line.ptr, packet->user_agent_line.len);

  if (flow->http.url == NULL && packet->http_url_name.len > 0)
  {
    flow->http.url = ndpi_malloc(packet->http_url_name.len + 1);
    if (flow->http.url != NULL)
    {
      strncpy(flow->http.url, (char const *)packet->http_url_name.ptr, packet->http_url_name.len);
      flow->http.url[packet->http_url_name.len] = '\0';
    }
  }

  return 0;
}

static void ndpi_search_fastcgi(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  struct FCGI_Header const * fcgi_hdr;
  enum FCGI_Type fcgi_type;
  u_int16_t content_len;
  ndpi_protocol_match_result ret_match;

  NDPI_LOG_DBG(ndpi_struct, "search fastcgi\n");

  if (packet->payload_packet_len < sizeof(struct FCGI_Header))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  fcgi_hdr = (struct FCGI_Header const *)&packet->payload[0];

  if (fcgi_hdr->version != 0x01)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  fcgi_type = (enum FCGI_Type)fcgi_hdr->type;
  if (fcgi_type < FCGI_MIN || fcgi_type > FCGI_MAX)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  content_len = ntohs(fcgi_hdr->contentLength);
  if (packet->payload_packet_len != sizeof(*fcgi_hdr) + content_len + fcgi_hdr->paddingLength)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (fcgi_type == FCGI_PARAMS)
  {
    if (content_len == 0)
    {
      flow->max_extra_packets_to_check = 0;
      flow->extra_packets_func = NULL;
      return;
    }

    if (fcgi_parse_params(flow, packet) != 0)
    {
      ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid FastCGI PARAMS header");
      ndpi_int_fastcgi_add_connection(ndpi_struct, flow, NULL);
    } else {
      ndpi_match_host_subprotocol(ndpi_struct, flow,
                                  flow->host_server_name,
                                  strlen(flow->host_server_name),
                                  &ret_match, NDPI_PROTOCOL_FASTCGI);
      ndpi_check_dga_name(ndpi_struct, flow,
                          flow->host_server_name, 1, 0);
      if(ndpi_is_valid_hostname((char *)packet->host_line.ptr,
                                packet->host_line.len) == 0) {
        char str[128];

        snprintf(str, sizeof(str), "Invalid host %s", flow->host_server_name);
        ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, str);

        /* This looks like an attack */
        ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, "Suspicious hostname: attack ?");
      }
      ndpi_int_fastcgi_add_connection(ndpi_struct, flow, &ret_match);
    }
    return;
  }

  if (flow->packet_counter > 2)
  {
    ndpi_int_fastcgi_add_connection(ndpi_struct, flow, NULL);
  }
}

static int ndpi_search_fastcgi_extra(struct ndpi_detection_module_struct * ndpi_struct,
                                     struct ndpi_flow_struct * flow)
{
  ndpi_search_fastcgi(ndpi_struct, flow);

  return flow->extra_packets_func != NULL;
}

void init_fastcgi_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                            u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("FastCGI", ndpi_struct, *id,
    NDPI_PROTOCOL_FASTCGI,
    ndpi_search_fastcgi,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );

  *id += 1;
}
