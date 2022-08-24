/*
 * fastcgi.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FASTCGI

#include "ndpi_api.h"

/* Reference: http://www.mit.edu/~yandros/doc/specs/fcgi-spec.html */

PACK_ON
struct FCGI_Header {
  unsigned char version;
  unsigned char type;
  u_int16_t requestId;
  u_int16_t contentLength;
  unsigned char paddingLength;
  unsigned char reserved;
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

static void ndpi_int_fastcgi_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                            struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found fastcgi\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_FASTCGI,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

void ndpi_search_fastcgi(struct ndpi_detection_module_struct *ndpi_struct,
                         struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  struct FCGI_Header const * fcgi_hdr;
  enum FCGI_Type fcgi_type;
  u_int16_t content_len;

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

  if (flow->packet_counter > 2)
  {
    ndpi_int_fastcgi_add_connection(ndpi_struct, flow);
  }
}

void init_fastcgi_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                            u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("FastCGI", ndpi_struct, detection_bitmask, *id,
    NDPI_PROTOCOL_FASTCGI,
    ndpi_search_fastcgi,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );

  *id += 1;
}
