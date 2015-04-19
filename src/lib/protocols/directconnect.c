/*
 * directconnect.c
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


#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_DIRECTCONNECT

//#define NDPI_DEBUG_DIRECTCONNECT
//#define NDPI_DIRECTCONNECT_PORT_DEBUG
//#define NDPI_DEBUG_DIRECTCONNECT_CONN


#define DIRECT_CONNECT_TYPE_HUB  0
#define DIRECT_CONNECT_TYPE_PEER 1
#define DIRECT_CONNECT_ADC_PEER  2

static u_int32_t skip_unknown_headers(const u_int8_t * payload, u_int32_t payload_len, u_int32_t pos)
{
  u_int32_t i = pos;
  while (i < payload_len && payload[i] != 0x0a)
    i++;

  i++;
  return i;

}

static u_int16_t parse_binf_message(struct ndpi_detection_module_struct
				    *ndpi_struct, const u_int8_t * payload, int payload_len)
{
  u_int32_t i = 4;
  u_int16_t bytes_read = 0;
  u_int16_t ssl_port = 0;
  while (i < payload_len) {
    i = skip_unknown_headers(payload, payload_len, i);
    if ((i + 30) < payload_len) {
      if (memcmp(&payload[i], "DCTM", 4) == 0) {
	if (memcmp(&payload[i + 15], "ADCS", 4) == 0) {
	  ssl_port = ntohs_ndpi_bytestream_to_number(&payload[i + 25], 5, &bytes_read);
	  NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		   NDPI_LOG_DEBUG, "directconnect ssl port parsed %d", ssl_port);

	}
      }
    } else {
      break;
    }

  }
  return ssl_port;
}

static void ndpi_int_directconnect_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
						  struct ndpi_flow_struct *flow,
						  const u_int8_t connection_type)
{

  struct ndpi_packet_struct *packet = &flow->packet;
	
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DIRECTCONNECT, NDPI_REAL_PROTOCOL);

  if (src != NULL) {
    src->directconnect_last_safe_access_time = packet->tick_timestamp;
    if (connection_type == DIRECT_CONNECT_TYPE_PEER) {
      if (packet->tcp != NULL
	  && flow->setup_packet_direction != packet->packet_direction && src->detected_directconnect_port == 0) {
	src->detected_directconnect_port = packet->tcp->source;
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "directconnect tcp PORT %u for src\n", ntohs(src->detected_directconnect_port));
      }
      if (packet->udp != NULL && src->detected_directconnect_udp_port == 0) {
	src->detected_directconnect_udp_port = packet->udp->source;
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "directconnect udp PORT %u for src\n", ntohs(src->detected_directconnect_port));

      }
    }

  }
  if (dst != NULL) {
    dst->directconnect_last_safe_access_time = packet->tick_timestamp;
    if (connection_type == DIRECT_CONNECT_TYPE_PEER) {
      if (packet->tcp != NULL
	  && flow->setup_packet_direction == packet->packet_direction && dst->detected_directconnect_port == 0) {
	/* DST PORT MARKING CAN LEAD TO PORT MISSDETECTIONS
	 * seen at large customer http servers, where someone has send faked DC tcp packets
	 * to the server
	 */

	/*
	  dst->detected_directconnect_port = packet->tcp->dest;
	  NDPI_LOG (NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
	  NDPI_LOG_DEBUG, "directconnect tcp PORT %u for dst\n",
	  ntohs (dst->detected_directconnect_port));
	*/
      }
    }
  }
}

static void ndpi_search_directconnect_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_DIRECTCONNECT) {
    if (packet->payload_packet_len >= 40 && memcmp(&packet->payload[0], "BINF", 4) == 0) {
      u_int16_t ssl_port = 0;
      ssl_port = parse_binf_message(ndpi_struct, &packet->payload[4], packet->payload_packet_len - 4);
      if (dst != NULL && ssl_port) {
	dst->detected_directconnect_ssl_port = ssl_port;
      }
      if (src != NULL && ssl_port) {
	src->detected_directconnect_ssl_port = ssl_port;
      }


    }
    if ((packet->payload_packet_len >= 38 && packet->payload_packet_len <= 42)
	&& memcmp(&packet->payload[0], "DCTM", 4) == 0 && memcmp(&packet->payload[15], "ADCS", 4) == 0) {
      u_int16_t bytes_read = 0;
      if (dst != NULL) {
	dst->detected_directconnect_ssl_port =
	  ntohs_ndpi_bytestream_to_number(&packet->payload[25], 5, &bytes_read);
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "directconnect ssl port parsed %d", ntohs(dst->detected_directconnect_ssl_port));
      }
      if (src != NULL) {
	src->detected_directconnect_ssl_port =
	  ntohs_ndpi_bytestream_to_number(&packet->payload[25], 5, &bytes_read);
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "directconnect ssl port parsed %d", ntohs(src->detected_directconnect_ssl_port));
      }


    }
    return;

  }
  if (src != NULL) {
    if (src->detected_directconnect_port == packet->tcp->source) {
      if ((u_int32_t)
	  (packet->tick_timestamp -
	   src->directconnect_last_safe_access_time) < ndpi_struct->directconnect_connection_ip_tick_timeout) {
	ndpi_int_change_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DIRECTCONNECT, NDPI_REAL_PROTOCOL);
	src->directconnect_last_safe_access_time = packet->tick_timestamp;
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "marking using dc port\n %d", ntohs(src->detected_directconnect_port));
	return;
      } else {
	src->detected_directconnect_port = 0;
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "resetting src port due to timeout");
	return;
      }
    }
    if (src->detected_directconnect_ssl_port == packet->tcp->dest) {
      if ((u_int32_t)
	  (packet->tick_timestamp -
	   src->directconnect_last_safe_access_time) < ndpi_struct->directconnect_connection_ip_tick_timeout) {
	ndpi_int_change_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DIRECTCONNECT, NDPI_REAL_PROTOCOL);
	src->directconnect_last_safe_access_time = packet->tick_timestamp;
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "marking using dc port\n %d", ntohs(src->detected_directconnect_ssl_port));
	return;
      } else {
	src->detected_directconnect_ssl_port = 0;
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "resetting src port due to timeout");
	return;
      }
    }

  }

  if (dst != NULL) {
    if (dst->detected_directconnect_port == packet->tcp->dest) {
      if ((u_int32_t)
	  (packet->tick_timestamp -
	   dst->directconnect_last_safe_access_time) < ndpi_struct->directconnect_connection_ip_tick_timeout) {
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DIRECTCONNECT, NDPI_REAL_PROTOCOL);
	dst->directconnect_last_safe_access_time = packet->tick_timestamp;
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "marking using dc port\n %d", ntohs(dst->detected_directconnect_port));
	return;
      } else {
	dst->detected_directconnect_port = 0;
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "resetting dst port due to timeout");
	return;
      }
    }
    if (dst->detected_directconnect_ssl_port == packet->tcp->dest) {
      if ((u_int32_t)
	  (packet->tick_timestamp -
	   dst->directconnect_last_safe_access_time) < ndpi_struct->directconnect_connection_ip_tick_timeout) {
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DIRECTCONNECT, NDPI_REAL_PROTOCOL);
	dst->directconnect_last_safe_access_time = packet->tick_timestamp;
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "marking using dc port\n %d", ntohs(dst->detected_directconnect_ssl_port));

	return;
      } else {
	dst->detected_directconnect_ssl_port = 0;
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "resetting dst port due to timeout");
	return;
      }
    }

  }

  if (flow->directconnect_stage == 0) {

    if (packet->payload_packet_len > 6) {
      if (packet->payload[0] == '$'
	  && packet->payload[packet->payload_packet_len - 1] == '|'
	  && (memcmp(&packet->payload[1], "Lock ", 5) == 0)) {
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "maybe first dc connect to hub  detected\n");
	flow->directconnect_stage = 1;
	return;
      }
      if (packet->payload_packet_len > 7
	  && packet->payload[0] == '$'
	  && packet->payload[packet->payload_packet_len - 1] == '|'
	  && (memcmp(&packet->payload[1], "MyNick ", 7) == 0)) {
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "maybe first dc connect between peers  detected\n");
	flow->directconnect_stage = 2;
	return;
      }

    }
    if (packet->payload_packet_len >= 11) {
      /* did not see this pattern in any trace */
      if (memcmp(&packet->payload[0], "HSUP ADBAS0", 11) == 0
	  || memcmp(&packet->payload[0], "HSUP ADBASE", 11) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "found directconnect HSUP ADBAS0 E\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_TYPE_HUB);
	return;
	/* did not see this pattern in any trace */
      } else if (memcmp(&packet->payload[0], "CSUP ADBAS0", 11) == 0 ||
		 memcmp(&packet->payload[0], "CSUP ADBASE", 11) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "found directconnect CSUP ADBAS0 E\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_ADC_PEER);
	return;

      }

    }

  } else if (flow->directconnect_stage == 1) {
    if (packet->payload_packet_len >= 11) {
      /* did not see this pattern in any trace */
      if (memcmp(&packet->payload[0], "HSUP ADBAS0", 11) == 0
	  || memcmp(&packet->payload[0], "HSUP ADBASE", 11) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "found directconnect HSUP ADBAS E in second packet\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_TYPE_HUB);

	return;
	/* did not see this pattern in any trace */
      } else if (memcmp(&packet->payload[0], "CSUP ADBAS0", 11) == 0 ||
		 memcmp(&packet->payload[0], "CSUP ADBASE", 11) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "found directconnect HSUP ADBAS0 E in second packet\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_ADC_PEER);


	return;

      }
    }
    /* get client hello answer or server message */
    if (packet->payload_packet_len > 6) {
      if ((packet->payload[0] == '$' || packet->payload[0] == '<')
	  && packet->payload[packet->payload_packet_len - 1] == '|') {
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct, NDPI_LOG_DEBUG, "second dc detected\n");
	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_TYPE_HUB);

	return;
      } else {
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct, NDPI_LOG_DEBUG, "second dc not detected\n");
      }

    }
  } else if (flow->directconnect_stage == 2) {
    /* get client hello answer or server message */
    if (packet->payload_packet_len > 6) {
      if (packet->payload[0] == '$' && packet->payload[packet->payload_packet_len - 1] == '|') {
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "second dc between peers detected\n");


	ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_TYPE_PEER);

	return;
      } else {
	NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
		 NDPI_LOG_DEBUG, "second dc between peers not detected\n");
      }
    }

  }


  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DIRECTCONNECT);

}

static void ndpi_search_directconnect_udp(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;
  int pos, count = 0;


  if (dst != NULL && dst->detected_directconnect_udp_port == packet->udp->dest) {
    if ((u_int32_t)
	(packet->tick_timestamp -
	 dst->directconnect_last_safe_access_time) < ndpi_struct->directconnect_connection_ip_tick_timeout) {

      ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_DIRECTCONNECT, NDPI_REAL_PROTOCOL);
      dst->directconnect_last_safe_access_time = packet->tick_timestamp;
      NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
	       NDPI_LOG_DEBUG, "marking using dc udp port\n %d", ntohs(dst->detected_directconnect_udp_port));
      return;
    } else {
      dst->detected_directconnect_udp_port = 0;
      NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
	       NDPI_LOG_DEBUG, "resetting dst udp  port due to timeout");
      return;
    }
  }

  if (packet->payload_packet_len > 58) {
    if (src != NULL
	&& NDPI_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, NDPI_PROTOCOL_DIRECTCONNECT)) {
      if (packet->payload[0] == '$'
	  && packet->payload[packet->payload_packet_len - 1] == '|'
	  && memcmp(&packet->payload[1], "SR ", 3) == 0) {
	pos = packet->payload_packet_len - 2;
	if (packet->payload[pos] == ')') {
	  while (pos > 0 && packet->payload[pos] != '(' && count < 21) {
	    pos--;
	    count++;
	  }
	  if (packet->payload[pos] == '(') {
	    pos = pos - 44;
	    if (pos > 2 && memcmp(&packet->payload[pos], "TTH:", 4) == 0) {
	      NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct, NDPI_LOG_DEBUG, "dc udp detected\n");
	      ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_TYPE_PEER);
	      return;
	    }
	  }
	}
	flow->directconnect_stage++;

	if (flow->directconnect_stage < 3) {


	  return;
	}

      }

    }
    if (dst != NULL
	&& NDPI_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, NDPI_PROTOCOL_DIRECTCONNECT)) {
      if (packet->payload[0] == '$'
	  && packet->payload[packet->payload_packet_len - 1] == '|'
	  && memcmp(&packet->payload[1], "SR ", 3) == 0) {
	pos = packet->payload_packet_len - 2;
	if (packet->payload[pos] == ')') {
	  while (pos > 0 && packet->payload[pos] != '(' && count < 21) {
	    pos--;
	    count++;
	  }
	  if (packet->payload[pos] == '(') {
	    pos = pos - 44;
	    if (pos > 2 && memcmp(&packet->payload[pos], "TTH:", 4) == 0) {
	      NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct, NDPI_LOG_DEBUG, "dc udp detected\n");
	      ndpi_int_directconnect_add_connection(ndpi_struct, flow, DIRECT_CONNECT_TYPE_PEER);
	      return;
	    }
	  }
	}
	flow->directconnect_stage++;
	if (flow->directconnect_stage < 3)
	  return;

      }
    }

  }
  NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct, NDPI_LOG_DEBUG,
	   "excluded at stage %d \n", flow->directconnect_stage);



  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DIRECTCONNECT);


}

void ndpi_search_directconnect(struct ndpi_detection_module_struct
			       *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;



  if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_DIRECTCONNECT) {
    if (src != NULL && ((u_int32_t)
			(packet->tick_timestamp -
			 src->directconnect_last_safe_access_time) <
			ndpi_struct->directconnect_connection_ip_tick_timeout)) {
      src->directconnect_last_safe_access_time = packet->tick_timestamp;

    } else if (dst != NULL && ((u_int32_t)
			       (packet->tick_timestamp -
				dst->directconnect_last_safe_access_time) <
			       ndpi_struct->directconnect_connection_ip_tick_timeout)) {
      dst->directconnect_last_safe_access_time = packet->tick_timestamp;
    } else {
      packet->detected_protocol_stack[0] = NDPI_PROTOCOL_UNKNOWN;
      NDPI_LOG(NDPI_PROTOCOL_DIRECTCONNECT, ndpi_struct,
	       NDPI_LOG_DEBUG, "directconnect: skipping as unknown due to timeout\n");
    }
    return;
  }

  if (packet->tcp != NULL) {
    ndpi_search_directconnect_tcp(ndpi_struct, flow);
  } else if (packet->udp != NULL) {
    ndpi_search_directconnect_udp(ndpi_struct, flow);
  }
}

#endif
