/*
 * jabber.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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

#ifdef NDPI_PROTOCOL_UNENCRYPTED_JABBER

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNENCRYPTED_JABBER

#include "ndpi_api.h"

struct jabber_string {
  char *string;
  u_int ndpi_protocol;
};

static struct jabber_string jabber_strings[] = {
#ifdef NDPI_PROTOCOL_TRUPHONE
  { "='im.truphone.com'",     NDPI_PROTOCOL_TRUPHONE },
  { "=\"im.truphone.com\"",   NDPI_PROTOCOL_TRUPHONE },
#endif
  { NULL, 0 }
};

static void ndpi_int_jabber_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow,
					   u_int32_t protocol)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_UNKNOWN);
}

static void check_content_type_and_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						   struct ndpi_flow_struct *flow, u_int16_t x)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  int i, left = packet->payload_packet_len-x;

  if(left <= 0) return;

  for(i=0; jabber_strings[i].string != NULL; i++) {
    if(ndpi_strnstr((const char*)&packet->payload[x], jabber_strings[i].string, left) != NULL) {    
      ndpi_int_jabber_add_connection(ndpi_struct, flow, jabber_strings[i].ndpi_protocol);
      return;
    }
  }  
}

void ndpi_search_jabber_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  u_int16_t x;

  NDPI_LOG_DBG(ndpi_struct, "search JABBER\n");

  /* search for jabber file transfer */
  /* this part is working asymmetrically */
  if (packet->tcp != NULL && packet->tcp->syn != 0 && packet->payload_packet_len == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "check jabber syn\n");
    if (src != NULL && src->jabber_file_transfer_port[0] != 0) {
      NDPI_LOG_DBG2(ndpi_struct, "src jabber ft port set, ports are: %u, %u\n",
		ntohs(src->jabber_file_transfer_port[0]),
		ntohs(src->jabber_file_transfer_port[1]));
      if (((u_int32_t)
	   (packet->tick_timestamp - src->jabber_stun_or_ft_ts)) >= ndpi_struct->jabber_file_transfer_timeout) {
	NDPI_LOG_DBG2(ndpi_struct, "JABBER src stun timeout %u %u\n",
			src->jabber_stun_or_ft_ts, packet->tick_timestamp);
	src->jabber_file_transfer_port[0] = 0;
	src->jabber_file_transfer_port[1] = 0;
      } else if (src->jabber_file_transfer_port[0] == packet->tcp->dest
		 || src->jabber_file_transfer_port[0] == packet->tcp->source
		 || src->jabber_file_transfer_port[1] == packet->tcp->dest
		 || src->jabber_file_transfer_port[1] == packet->tcp->source) {
	NDPI_LOG_INFO(ndpi_struct, "found jabber file transfer\n");

	ndpi_int_jabber_add_connection(ndpi_struct, flow,
				       NDPI_PROTOCOL_UNENCRYPTED_JABBER);
      }
    }
    if (dst != NULL && dst->jabber_file_transfer_port[0] != 0) {
      NDPI_LOG_DBG2(ndpi_struct, "dst jabber ft port set, ports are: %u, %u\n",
		ntohs(dst->jabber_file_transfer_port[0]),
		ntohs(dst->jabber_file_transfer_port[1]));
      if (((u_int32_t)
	   (packet->tick_timestamp - dst->jabber_stun_or_ft_ts)) >= ndpi_struct->jabber_file_transfer_timeout) {
	NDPI_LOG_DBG2(ndpi_struct, "JABBER dst stun timeout %u %u\n",
			dst->jabber_stun_or_ft_ts, packet->tick_timestamp);
	dst->jabber_file_transfer_port[0] = 0;
	dst->jabber_file_transfer_port[1] = 0;
      } else if (dst->jabber_file_transfer_port[0] == packet->tcp->dest
		 || dst->jabber_file_transfer_port[0] == packet->tcp->source
		 || dst->jabber_file_transfer_port[1] == packet->tcp->dest
		 || dst->jabber_file_transfer_port[1] == packet->tcp->source) {
	NDPI_LOG_INFO(ndpi_struct, "found jabber file transfer\n");

	ndpi_int_jabber_add_connection(ndpi_struct, flow,
				       NDPI_PROTOCOL_UNENCRYPTED_JABBER);
      }
    }
    return;
  }

  if (packet->tcp != 0 && packet->payload_packet_len == 0) {
    return;
  }


  /* this part parses a packet and searches for port=. it works asymmetrically. */
  if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNENCRYPTED_JABBER) {
    u_int16_t lastlen;
    u_int16_t j_port = 0;
    /* check for google jabber voip connections ... */
    /* need big packet */
    if (packet->payload_packet_len < 100) {
      NDPI_LOG_DBG2(ndpi_struct, "packet too small, return\n");
      return;
    }
    /* need message to or type for file-transfer */
    if (memcmp(packet->payload, "<iq from=\"", 8) == 0 || memcmp(packet->payload, "<iq from=\'", 8) == 0) {
      NDPI_LOG_DBG2(ndpi_struct, "JABBER <iq from=\"\n");
      lastlen = packet->payload_packet_len - 11;
      for (x = 10; x < lastlen; x++) {
	if (packet->payload[x] == 'p') {
	  if (memcmp(&packet->payload[x], "port=", 5) == 0) {
	    NDPI_LOG_DBG2(ndpi_struct, "port=\n");
	    if (src != NULL) {
	      src->jabber_stun_or_ft_ts = packet->tick_timestamp;
	    }

	    if (dst != NULL) {
	      dst->jabber_stun_or_ft_ts = packet->tick_timestamp;
	    }
	    x += 6;
	    j_port = ntohs_ndpi_bytestream_to_number(&packet->payload[x], packet->payload_packet_len, &x);
	    NDPI_LOG_DBG2(ndpi_struct, "JABBER port : %u\n", ntohs(j_port));
	    if (src != NULL) {
	      if (src->jabber_file_transfer_port[0] == 0 || src->jabber_file_transfer_port[0] == j_port) {
		NDPI_LOG_DBG2(ndpi_struct, "src->jabber_file_transfer_port[0] = j_port = %u;\n",
			 ntohs(j_port));
		src->jabber_file_transfer_port[0] = j_port;
	      } else {
		NDPI_LOG_DBG2(ndpi_struct, "src->jabber_file_transfer_port[1] = j_port = %u;\n",
			 ntohs(j_port));
		src->jabber_file_transfer_port[1] = j_port;
	      }
	    }
	    if (dst != NULL) {
	      if (dst->jabber_file_transfer_port[0] == 0 || dst->jabber_file_transfer_port[0] == j_port) {
		NDPI_LOG_DBG2(ndpi_struct, "dst->jabber_file_transfer_port[0] = j_port = %u;\n",
			 ntohs(j_port));
		dst->jabber_file_transfer_port[0] = j_port;
	      } else {
		NDPI_LOG_DBG2(ndpi_struct, "dst->jabber_file_transfer_port[1] = j_port = %u;\n",
			 ntohs(j_port));
		dst->jabber_file_transfer_port[1] = j_port;
	      }
	    }
	  }


	}
      }

    } else if (memcmp(packet->payload, "<iq to=\"", 8) == 0 || memcmp(packet->payload, "<iq to=\'", 8) == 0
	       || memcmp(packet->payload, "<iq type=", 9) == 0) {
      NDPI_LOG_DBG2(ndpi_struct, "JABBER <iq to=\"/type=\"\n");
      lastlen = packet->payload_packet_len - 21;
      for (x = 8; x < lastlen; x++) {
	/* invalid character */
	if (packet->payload[x] < 32 || packet->payload[x] > 127) {
	  return;
	}
	if (packet->payload[x] == '@') {
	  NDPI_LOG_DBG2(ndpi_struct, "JABBER @\n");
	  break;
	}
      }
      if (x >= lastlen) {
	return;
      }

      lastlen = packet->payload_packet_len - 10;
      for (; x < lastlen; x++) {
	if (packet->payload[x] == 'p') {
	  if (memcmp(&packet->payload[x], "port=", 5) == 0) {
	    NDPI_LOG_DBG2(ndpi_struct, "port=\n");
	    if (src != NULL) {
	      src->jabber_stun_or_ft_ts = packet->tick_timestamp;
	    }

	    if (dst != NULL) {
	      dst->jabber_stun_or_ft_ts = packet->tick_timestamp;
	    }

	    x += 6;
	    j_port = ntohs_ndpi_bytestream_to_number(&packet->payload[x], packet->payload_packet_len, &x);
	    NDPI_LOG_DBG2(ndpi_struct, "JABBER port : %u\n", ntohs(j_port));

	    if (src != NULL && src->jabber_voice_stun_used_ports < JABBER_MAX_STUN_PORTS - 1) {
	      if (packet->payload[5] == 'o') {
		src->jabber_voice_stun_port[src->jabber_voice_stun_used_ports++]
		  = j_port;
	      } else {
		if (src->jabber_file_transfer_port[0] == 0
		    || src->jabber_file_transfer_port[0] == j_port) {
		  NDPI_LOG_DBG2(ndpi_struct, "src->jabber_file_transfer_port[0] = j_port = %u;\n",
				ntohs(j_port));
		  src->jabber_file_transfer_port[0] = j_port;
		} else {
		  NDPI_LOG_DBG2(ndpi_struct, "src->jabber_file_transfer_port[1] = j_port = %u;\n",
				ntohs(j_port));
		  src->jabber_file_transfer_port[1] = j_port;
		}
	      }
	    }

	    if (dst != NULL && dst->jabber_voice_stun_used_ports < JABBER_MAX_STUN_PORTS - 1) {
	      if (packet->payload[5] == 'o') {
		dst->jabber_voice_stun_port[dst->jabber_voice_stun_used_ports++]
		  = j_port;
	      } else {
		if (dst->jabber_file_transfer_port[0] == 0
		    || dst->jabber_file_transfer_port[0] == j_port) {
		  NDPI_LOG_DBG2(ndpi_struct, "dst->jabber_file_transfer_port[0] = j_port = %u;\n",
				  ntohs(j_port));
		  dst->jabber_file_transfer_port[0] = j_port;
		} else {
		  NDPI_LOG_DBG2(ndpi_struct, "dst->jabber_file_transfer_port[1] = j_port = %u;\n",
				  ntohs(j_port));
		  dst->jabber_file_transfer_port[1] = j_port;
		}
	      }
	    }
	    return;
	  }
	}
      }
    }
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
      ndpi_int_jabber_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNENCRYPTED_JABBER);

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

#ifdef NDPI_PROTOCOL_TRUPHONE
  ndpi_exclude_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TRUPHONE,__FILE__,__FUNCTION__,__LINE__);
#endif
}


void init_jabber_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Unencrypted_Jabber", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_UNENCRYPTED_JABBER,
				      ndpi_search_jabber_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
#endif
