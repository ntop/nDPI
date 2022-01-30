/*
 * jabber.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
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

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_JABBER

#include "ndpi_api.h"

struct jabber_string {
  char *string;
  u_int ndpi_protocol;
};

static struct jabber_string jabber_strings[] = {
  { "='im.truphone.com'",     NDPI_PROTOCOL_TRUPHONE },
  { "=\"im.truphone.com\"",   NDPI_PROTOCOL_TRUPHONE },
  { NULL, 0 }
};

static void ndpi_int_jabber_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow,
					   u_int32_t protocol, ndpi_confidence_t confidence)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_UNKNOWN, confidence);
}

static void check_content_type_and_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						   struct ndpi_flow_struct *flow, u_int16_t x)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int i, left = packet->payload_packet_len-x;

  if(left <= 0) return;

  for(i=0; jabber_strings[i].string != NULL; i++) {
    if(ndpi_strnstr((const char*)&packet->payload[x], jabber_strings[i].string, left) != NULL) {    
      ndpi_int_jabber_add_connection(ndpi_struct, flow, jabber_strings[i].ndpi_protocol, NDPI_CONFIDENCE_DPI);
      return;
    }
  }  
}

void ndpi_search_jabber_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search JABBER\n");

  if (flow->packet_counter > 5) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  
  if (packet->tcp != 0 && packet->payload_packet_len == 0) {
    return;
  }

  /* search for jabber here */
  /* this part is working asymmetrically */
  if ((packet->payload_packet_len > 13 && memcmp(packet->payload, "<?xml version=", 14) == 0)
      || (packet->payload_packet_len >= NDPI_STATICSTRING_LEN("<stream:stream ")
	  && memcmp(packet->payload, "<stream:stream ", NDPI_STATICSTRING_LEN("<stream:stream ")) == 0)) {
    int start = packet->payload_packet_len-13;

    if(ndpi_strnstr((const char *)&packet->payload[13], "xmlns:stream='http://etherx.jabber.org/streams'", start)
       || ndpi_strnstr((const char *)&packet->payload[13], "xmlns:stream=\"http://etherx.jabber.org/streams\"", start)) {
  
      /* Protocol family */
      ndpi_int_jabber_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_JABBER, NDPI_CONFIDENCE_DPI);

      /* search for subprotocols */
      check_content_type_and_change_protocol(ndpi_struct, flow, 13);
      return;
    }
  }
  
  if (flow->packet_counter < 3) {
    NDPI_LOG_DBG2(ndpi_struct, "packet_counter: %u\n", flow->packet_counter);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

  ndpi_exclude_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TRUPHONE,
			__FILE__,__FUNCTION__,__LINE__);
}


void init_jabber_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Jabber", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_JABBER,
				      ndpi_search_jabber_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

