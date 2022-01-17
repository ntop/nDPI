/*
 * netbios.c
 *
 * Copyright (C) 2011-22 - ntop.org
 * Copyright (C) 2009-11 - ipoque GmbH
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NETBIOS

#include "ndpi_api.h"

/* ****************************************************************** */

struct netbios_header {
  u_int16_t transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs;
};

/* ****************************************************************** */

static int is_printable_char(unsigned char c) {
  return(((c >= 0x20) && (c <= 0x7e)) ? 1 : 0);
}

/* ****************************************************************** */

static int is_stop_char(u_char c) {
  return(((c < 'A') || (c > 'P')) ? 1 : 0);
}

/* ****************************************************************** */

/* The function below has been inherited by tcpdump */
int ndpi_netbios_name_interpret(u_char *in, u_int in_len, u_char *out, u_int out_len) {
  u_int ret = 0, len, idx = in_len, out_idx = 0;

  len = in[0] / 2;
  in++, in_len--;
  
  out_len--;
  out[out_idx] = 0;

  if((len > out_len) || (len < 1) || ((2*len) > in_len))
    return(-1);

  while((len--) && (out_idx < out_len)) {
    if((idx < 2) || is_stop_char(in[0]) || is_stop_char(in[1])) {
      out[out_idx] = 0;
      break;
    }

    out[out_idx] = ((in[0] - 'A') << 4) + (in[1] - 'A');
    in += 2, idx -= 2;

    if(is_printable_char(out[out_idx]))
      out_idx++, ret++;
  }

  /* Trim trailing whitespace from the returned string */
  if(out_idx > 0) {
    out[out_idx] = 0;
    out_idx--;

    while((out_idx > 0) && (out[out_idx] == ' ')) {
      out[out_idx] = 0;
      out_idx--;
    }
  }

  return(ret);
}

/* ****************************************************************** */

static void ndpi_int_netbios_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					    u_int16_t sub_protocol) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  unsigned char name[64];
  u_int off = packet->payload[12] == 0x20 ? 12 : 14;

  if((off < packet->payload_packet_len)
     && ndpi_netbios_name_interpret((unsigned char*)&packet->payload[off],
		 (u_int)(packet->payload_packet_len - off), name, sizeof(name)-1) > 0) {
      ndpi_hostname_sni_set(flow, (const u_int8_t *)name, strlen((char *)name));

      ndpi_check_dga_name(ndpi_struct, flow, flow->host_server_name, 1);
  }

  if(sub_protocol == NDPI_PROTOCOL_UNKNOWN)
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NETBIOS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  else
    ndpi_set_detected_protocol(ndpi_struct, flow, sub_protocol, NDPI_PROTOCOL_NETBIOS, NDPI_CONFIDENCE_DPI);
}

/* ****************************************************************** */

void ndpi_search_netbios(struct ndpi_detection_module_struct *ndpi_struct,
			 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t dport;

  NDPI_LOG_DBG(ndpi_struct, "search netbios\n");

  if(packet->udp != NULL) {
    dport = ntohs(packet->udp->dest);

    /*check standard NETBIOS over udp to port 137  */
    if((dport == 137 || 0) && packet->payload_packet_len >= 50) {
      struct netbios_header h;

      memcpy(&h, packet->payload, sizeof(struct netbios_header));
      h.transaction_id = ntohs(h.transaction_id), h.flags = ntohs(h.flags),
	h.questions = ntohs(h.questions), h.answer_rrs = ntohs(h.answer_rrs),
	h.authority_rrs = ntohs(h.authority_rrs), h.additional_rrs = ntohs(h.additional_rrs);

      NDPI_LOG_DBG(ndpi_struct, "found netbios port 137 and payload_packet_len 50\n");

      if(h.flags == 0 &&
	 h.questions == 1 &&
	 h.answer_rrs == 0 &&
	 h.authority_rrs == 0 && h.additional_rrs == 0) {

	NDPI_LOG_INFO(ndpi_struct, "found netbios with questions = 1 and answers = 0, authority = 0  \n");

	ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	return;
      }

      if(((h.flags & 0x8710) == 0x10) &&
	 h.questions == 1 &&
	 h.answer_rrs == 0 &&
	 h.authority_rrs == 0) {

	NDPI_LOG_INFO(ndpi_struct, "found netbios with questions = 1 and answers = 0, authority = 0 and broadcast \n");

	ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	return;
      }

      if(packet->payload[2] == 0x80 &&
	 h.questions == 1 &&
	 h.answer_rrs == 0 &&
	 h.authority_rrs == 0 && h.additional_rrs == 1) {

	NDPI_LOG_INFO(ndpi_struct, "found netbios with questions = 1 and answers, authority, additional = 0  \n");

	ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	return;
      }

      if(h.flags == 0x4000 &&
	 h.questions == 1 &&
	 h.answer_rrs == 0 &&
	 h.authority_rrs == 0 && h.additional_rrs == 1) {

	NDPI_LOG_INFO(ndpi_struct, "found netbios with questions = 1 and answers = 0, authority = 0  \n");

	ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	return;
      }

      if(h.flags == 0x8400 &&
	 h.questions == 0 &&
	 h.answer_rrs == 1 &&
	 h.authority_rrs == 0 && h.additional_rrs == 0) {

	NDPI_LOG_INFO(ndpi_struct,
		      "found netbios with flag 8400 questions = 0 and answers = 1, authority, additional = 0  \n");

	ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	return;
      }

      if(h.flags == 0x8500 &&
	 h.questions == 0 &&
	 h.answer_rrs == 1 &&
	 h.authority_rrs == 0 && h.additional_rrs == 0) {

	NDPI_LOG_INFO(ndpi_struct,
		      "found netbios with flag 8500 questions = 0 and answers = 1, authority, additional = 0  \n");

	ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	return;
      }

      if(((h.flags == 0x2900) || (h.flags == 0x2910)) &&
	 h.questions == 1 &&
	 h.answer_rrs == 0 &&
	 h.authority_rrs == 0 && h.additional_rrs == 1) {

	NDPI_LOG_INFO(ndpi_struct,
		      "found netbios with flag 2910, questions = 1 and answers, authority=0, additional = 1  \n");

	ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	return;
      }

      if(h.flags == 0xAD86 &&
	 h.questions == 0 &&
	 h.answer_rrs == 1 &&
	 h.authority_rrs == 0 && h.additional_rrs == 0) {

	NDPI_LOG_INFO(ndpi_struct,
		      "found netbios with flag ad86 questions = 0 and answers = 1, authority, additional = 0  \n");

	ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	return;
      }

      if(h.flags == 0x0110 &&
	 h.questions == 1 &&
	 h.answer_rrs == 0 &&
	 h.authority_rrs == 0 && h.additional_rrs == 0) {

	NDPI_LOG_INFO(ndpi_struct,
		      "found netbios with flag 0110 questions = 1 and answers = 0, authority, additional = 0  \n");

	ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	return;
      }

      if((h.flags & 0xf800) == 0) {
	NDPI_LOG_DBG2(ndpi_struct, "possible netbios name query request\n");

	if(get_u_int16_t(packet->payload, 4) == htons(1) &&
	   get_u_int16_t(packet->payload, 6) == 0 &&
	   get_u_int16_t(packet->payload, 8) == 0 && get_u_int16_t(packet->payload, 10) == 0) {

	  /* name is encoded as described in rfc883 */
	  u_int8_t name_length = packet->payload[12];

	  NDPI_LOG_DBG2(ndpi_struct,
			"possible netbios name query request, one question\n");

	  if(packet->payload_packet_len == 12 + 1 + name_length + 1 + 2 + 2) {

	    NDPI_LOG_DBG2(ndpi_struct,
			  "possible netbios name query request, length matches\n");

	    /* null terminated? */
	    if(packet->payload[12 + name_length + 1] == 0 &&
	       get_u_int16_t(packet->payload, 12 + name_length + 2) == htons(0x0020) &&
	       get_u_int16_t(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

	      NDPI_LOG_INFO(ndpi_struct,
			    "found netbios name query request\n");
	      ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	      return;
	    }
	  }
	}
      } else if((h.flags & 0xf800) == 0x8000) {
	NDPI_LOG_DBG2(ndpi_struct,
		      "possible netbios name query response\n");

	if(get_u_int16_t(packet->payload, 4) == 0 &&
	   get_u_int16_t(packet->payload, 6) == htons(1) &&
	   get_u_int16_t(packet->payload, 8) == 0 && get_u_int16_t(packet->payload, 10) == 0) {

	  /* name is encoded as described in rfc883 */
	  u_int8_t name_length = packet->payload[12];

	  NDPI_LOG_DBG2(ndpi_struct,
			"possible netbios positive name query response, one answer\n");

	  if(packet->payload_packet_len >= 12 + 1 + name_length + 1 + 2 + 2) {

	    NDPI_LOG_DBG2(ndpi_struct,
			  "possible netbios name query response, length matches\n");

	    /* null terminated? */
	    if(packet->payload[12 + name_length + 1] == 0 &&
	       get_u_int16_t(packet->payload, 12 + name_length + 2) == htons(0x0020) &&
	       get_u_int16_t(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

	      NDPI_LOG_INFO(ndpi_struct,
			    "found netbios name query response\n");
	      ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	      return;
	    }
	  }
	} else if(get_u_int16_t(packet->payload, 4) == 0 &&
		  get_u_int16_t(packet->payload, 6) == 0 &&
		  get_u_int16_t(packet->payload, 8) == 0 && get_u_int16_t(packet->payload, 10) == 0) {

	  /* name is encoded as described in rfc883 */
	  u_int8_t name_length = packet->payload[12];

	  NDPI_LOG_DBG2(ndpi_struct,
			"possible netbios negative name query response, one answer\n");

	  if(packet->payload_packet_len >= 12 + 1 + name_length + 1 + 2 + 2) {

	    NDPI_LOG_DBG2(ndpi_struct,
			  "possible netbios name query response, length matches\n");

	    /* null terminated? */
	    if(packet->payload[12 + name_length + 1] == 0 &&
	       get_u_int16_t(packet->payload, 12 + name_length + 2) == htons(0x000A) &&
	       get_u_int16_t(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

	      NDPI_LOG_INFO(ndpi_struct,
			    "found netbios name query response\n");
	      ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	      return;
	    }
	  }
	} else if(get_u_int16_t(packet->payload, 4) == 0 &&
		  get_u_int16_t(packet->payload, 6) == 0 &&
		  get_u_int16_t(packet->payload, 8) == htons(1) && get_u_int16_t(packet->payload, 10) == htons(1)) {

	  /* name is encoded as described in rfc883 */
	  u_int8_t name_length = packet->payload[12];

	  NDPI_LOG_DBG2(ndpi_struct,
			"possible netbios redirect name query response, one answer\n");

	  if(packet->payload_packet_len >= 12 + 1 + name_length + 1 + 2 + 2) {

	    NDPI_LOG_DBG2(ndpi_struct,
			  "possible netbios name query response, length matches\n");

	    /* null terminated? */
	    if(packet->payload[12 + name_length + 1] == 0 &&
	       get_u_int16_t(packet->payload, 12 + name_length + 2) == htons(0x0002) &&
	       get_u_int16_t(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

	      NDPI_LOG_INFO(ndpi_struct,
			    "found netbios name query response\n");
	      ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	      return;
	    }
	  }
	}
      }
      /* TODO: extend according to rfc1002 */
    }

    /* check standard NETBIOS over udp to port 138 */

    /* netbios header token from http://www.protocolbase.net/protocols/protocol_NBDGM.php */

    if((dport == 138) && (packet->payload_packet_len >= 14)) {
      u_int16_t netbios_len = ntohs(get_u_int16_t(packet->payload, 10));

      if(netbios_len == packet->payload_packet_len - 14) {
	NDPI_LOG_DBG2(ndpi_struct, "found netbios port 138 and payload length >= 112 \n");

	/* TODO: ipv6 */
	if(packet->iph && packet->payload[0] >= 0x10 && packet->payload[0] <= 0x16) {
	  u_int32_t source_ip = ntohl(get_u_int32_t(packet->payload, 4));

	  NDPI_LOG_DBG2(ndpi_struct, "found netbios with MSG-type 0x10,0x11,0x12,0x13,0x14,0x15 or 0x16\n");

	  if(source_ip == ntohl(packet->iph->saddr)) {
	    int16_t leftover = netbios_len - 82; /* NetBIOS len */

	    NDPI_LOG_INFO(ndpi_struct, "found netbios with checked ip-address\n");

	    ndpi_int_netbios_add_connection(ndpi_struct, flow, (leftover > 0) ? NDPI_PROTOCOL_SMBV1 : NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	}
      }
    }
  }

  if(packet->tcp != NULL) {
    dport = ntohs(packet->tcp->dest);

    /* destination port must be 139 */
    if(dport == 139) {
      NDPI_LOG_DBG2(ndpi_struct, "found netbios with destination port 139\n");

      /* payload_packet_len must be 72 */
      if(packet->payload_packet_len == 72) {
	NDPI_LOG_DBG2(ndpi_struct, "found netbios with payload_packen_len = 72. \n");

	if(packet->payload[0] == 0x81 && packet->payload[1] == 0 && ntohs(get_u_int16_t(packet->payload, 2)) == 68) {
	  NDPI_LOG_INFO(ndpi_struct,
			"found netbios with session request = 81, flags=0 and length od following bytes = 68. \n");

	  ndpi_int_netbios_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
	  return;
	}
      }
    }

  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ****************************************************************** */

void init_netbios_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("NETBIOS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_NETBIOS,
				      ndpi_search_netbios,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
