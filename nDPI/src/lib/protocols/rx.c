/*
 * rx.c
 *
 * Copyright (C) 2012-16 - ntop.org
 *
 * Giovanni Mascellani <gio@debian.org>
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

#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_RX

/* See http://web.mit.edu/kolya/afs/rx/rx-spec for protocol description. */

/* The should be no need for explicit packing, but just in case... */
PACK_ON
struct ndpi_rx_header {
  u_int32_t conn_epoch;
  u_int32_t conn_id;
  u_int32_t call_number;
  u_int32_t sequence_number;
  u_int32_t serial_number;
  u_int8_t type;
  u_int8_t flags;
  u_int8_t status;
  u_int8_t security;
  u_int16_t checksum;
  u_int16_t service_id;
} PACK_OFF;

/* Type values */
#define DATA	           1
#define	ACK	           2
#define	BUSY	           3	
#define	ABORT	           4	
#define	ACKALL	           5	
#define	CHALLENGE          6	
#define	RESPONSE           7	
#define	DEBUG	           8	
#define	PARAM_1            9	
#define	PARAM_2           10	
#define	PARAM_3           11	
#define	PARAMS_4          12	
#define	VERSION	          13

/* Flags values */
#define EMPTY              0
#define CLIENT_INIT_1      1
#define REQ_ACK            2
#define PLUS_0             3
#define LAST_PKT           4
#define PLUS_1             5
#define PLUS_2             6
#define MORE_1             9
#define CLIENT_INIT_2     33



void ndpi_check_rx(struct ndpi_detection_module_struct *ndpi_struct,
                   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "RX: pck: %d, dir[0]: %d, dir[1]: %d\n",
           flow->packet_counter, flow->packet_direction_counter[0], flow->packet_direction_counter[1]);

  /* Check that packet is long enough */
  if (payload_len < sizeof(struct ndpi_rx_header)) {
    NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "excluding RX\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RX);
    return;
  }
  
  struct ndpi_rx_header *header = (struct ndpi_rx_header*) packet->payload;

  /**
   * Useless check: a session could be detected also after it starts 
   * and this check limit the correct detection for -d option (disable guess)
   * TODO - maybe to improve 
   **/
  /* Check whether the packet has counters beginning from one; the
     Sequence Number can be zero if the packet is just an ACK. */
  /* if ((ntohl(header->sequence_number) | 1) != 1 || ntohl(header->serial_number) != 1) */
  
  
  /**
   *  Check the TYPE and FLAGS fields of an RX packet header.
   *  This check is necessary because we could detect an RX session already begun 
  **/
  
  /* TYPE field */
  if((header->type < DATA) || (header->type > VERSION)) {
    NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "excluding RX\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RX);
    return;
  }

  /* FLAGS fields */
  if(header->flags == EMPTY || header->flags == LAST_PKT ||
     header->flags == PLUS_0 || header->flags == PLUS_1 ||
     header->flags == PLUS_2 || header->flags == REQ_ACK ||
     header->flags == MORE_1 || header->flags == CLIENT_INIT_1 ||
     header->flags == CLIENT_INIT_2) {

    /* TYPE and FLAGS combo */
    switch(header->type)
    {
      case DATA:
	if(header->flags == LAST_PKT || header->flags == EMPTY ||
	   header->flags == PLUS_0 || header->flags == PLUS_1 ||
	   header->flags == PLUS_2 || header->flags == REQ_ACK ||
	   header->flags == MORE_1)
	  goto security;
      case ACK:
	if(header->flags == CLIENT_INIT_1 || header->flags == CLIENT_INIT_2 ||
	   header->flags == EMPTY)
	  goto security;
      case CHALLENGE:
	if(header->flags == EMPTY || header->call_number == 0)
	  goto security;
      case RESPONSE:
	if(header->flags == EMPTY || header->call_number == 0)
	  goto security;
      case ACKALL:
	if(header->flags == EMPTY)
	  goto security;
      case BUSY:
	goto security;
      case ABORT:
	goto security;
      case DEBUG:
	goto security;
      case PARAM_1:
	goto security;
      case PARAM_2:
        goto security;
      case PARAM_3:
	goto security;
      case VERSION:
	goto security;
      default:
	NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "excluding RX\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RX);
	return;
    } // switch
  } else { // FLAG
    NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "excluding RX\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RX);
    return;
  }

 security:
  /* SECURITY field */
  if(header->security > 3)
  {
    NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "excluding RX\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RX);
    return;
  }
  
  /* If we have already seen one packet in the other direction, then
     the two must have matching connection numbers. Otherwise store
     them. */
  if(flow->packet_direction_counter[!packet->packet_direction] != 0)
  {
    if (flow->l4.udp.rx_conn_epoch == header->conn_epoch &&
	flow->l4.udp.rx_conn_id == header->conn_id)
    {
      NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "found RX\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RX, NDPI_PROTOCOL_UNKNOWN);
    }
    /* https://www.central.org/frameless/numbers/rxservice.html. */
    else
    {
      NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "excluding RX\n");
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RX);
      return;
    }
  } else {
    flow->l4.udp.rx_conn_epoch = header->conn_epoch;
    flow->l4.udp.rx_conn_id = header->conn_id;
    {
      NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "found RX\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RX, NDPI_PROTOCOL_UNKNOWN);
    }
  }
}

void ndpi_search_rx(struct ndpi_detection_module_struct *ndpi_struct,
                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "entering RX search\n");
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_RX) {
    ndpi_check_rx(ndpi_struct, flow);
  }
}

void init_rx_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                       u_int32_t *id,
                       NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("RX", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_RX,
				      ndpi_search_rx,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
