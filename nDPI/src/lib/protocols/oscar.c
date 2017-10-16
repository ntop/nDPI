/*
 * oscar.c
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


#include "ndpi_api.h"

#define FLAPVERSION         0x00000001

/* Flap channels */
#define SIGNON              0x01
#define DATA                0x02
#define O_ERROR               0x03
#define SIGNOFF             0x04
#define KEEP_ALIVE          0x05

/* Signon tags */
#define SCREEN_NAME         0x0001
#define PASSWD              0x0002
#define CLIENT_NAME	    0x0003
#define BOS                 0x0005
#define LOGIN_COOKIE	    0x0006
#define MAJOR_VERSION	    0x0017
#define MINOR_VERSION	    0x0018
#define POINT_VERSION	    0x0019
#define BUILD_NUM	    0x001a
#define MULTICONN_FLAGS	    0x004a
#define CLIENT_LANG         0x00OF
#define CLIENT_CNTRY        0x00OE
#define CLIENT_RECONNECT    0x0094

/* Family */
#define GE_SE_CTL           0x0001
#define LOC_SRV             0x0002
#define BUDDY_LIST          0x0003
#define IM                  0x0004
#define IS                  0x0006
#define ACC_ADM             0x0007
#define POPUP               0x0008
#define PMS                 0x0009
#define USS                 0x000b
#define CHAT_ROOM_SETUP     0x000d
#define CHAT_ROOM_ACT       0x000e
#define USER_SRCH	    0x000f
#define BUDDY_ICON_SERVER   0x0010
#define SERVER_STORED_INFO  0x0013
#define ICQ                 0x0015
#define INIT_AUTH           0x0017
#define EMAIL               0x0018
#define IS_EXT              0x0085

#ifdef NDPI_PROTOCOL_OSCAR

static void ndpi_int_oscar_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					  struct ndpi_flow_struct *flow)
{

  struct ndpi_packet_struct *packet = &flow->packet;
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OSCAR, NDPI_PROTOCOL_UNKNOWN);

  if (src != NULL) {
    src->oscar_last_safe_access_time = packet->tick_timestamp;
  }
  if (dst != NULL) {
    dst->oscar_last_safe_access_time = packet->tick_timestamp;
  }
}

/**
   Oscar connection work on FLAP protocol.

   FLAP is a low-level communications protocol that facilitates the development of higher-level, datagram-oriented, communications layers.
   It is used on the TCP connection between all clients and servers.
   Here is format of FLAP datagram
**/
static void ndpi_search_oscar_tcp_connect(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{

  int excluded = 0;
//  u_int8_t channel;
  u_int16_t family;
  u_int16_t type;
  u_int16_t flag;
  u_int32_t req_ID;

  struct ndpi_packet_struct * packet = &flow->packet;

  struct ndpi_id_struct * src = flow->src;
  struct ndpi_id_struct * dst = flow->dst;

  /* FLAP__Header
   *
   * [ 6 byte FLAP header ]
   * +-----------+--------------+-------------+--------------+
   * | 0x2a (1B) | Channel (1B) | SeqNum (2B) | PyldLen (2B) |
   * +-----------+--------------+-------------+--------------+
   *
   * [ 4 byte of data ]
   *
   * */
  if (packet->payload_packet_len >= 6 && packet->payload[0] == 0x2a)
    {

      /* FLAP__FRAME_TYPE (Channel)*/
      u_int8_t channel = get_u_int8_t(packet->payload, 1);

      /*
	 Initialize the FLAP connection.

	 SIGNON -> FLAP__SIGNON_FRAME
	 +--------------------------------------------------+
	 + FLAP__Header | 6 byte                            +
	 + FlapVersion  | 4 byte  (Always 1 = 0x00000001)   +
	 + TLVs         | [Class: FLAP__SIGNON_TAGS] TLVs   +
	 +--------------------------------------------------+
      */
      if (channel == SIGNON &&
	  get_u_int16_t(packet->payload, 4) == htons(packet->payload_packet_len - 6) &&
	  get_u_int32_t(packet->payload, 6) == htonl(FLAPVERSION))
	{

	  /* No TLVs */
	  if(packet->payload_packet_len == 10)
	    {
	      NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR - Sign In \n");
	      ndpi_int_oscar_add_connection(ndpi_struct, flow);
	      return;
	    }
	  /* /\* SCREEN_NAME *\/ */
	  /* if (get_u_int16_t(packet->payload, 10) == htons(SCREEN_NAME)) /\* packet->payload[10] == 0x00 && packet->payload[11] == 0x01 *\/ */
	  /*   { */
	  /*     NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR - Screen Name \n"); */
	  /*     ndpi_int_oscar_add_connection(ndpi_struct, flow); */
	  /*     return; */
	  /*   } */
	  /* /\* PASSWD *\/ */
	  /* if (get_u_int16_t(packet->payload, 10) == htons(PASSWD)) /\* packet->payload[10] == 0x00 && packet->payload[11] == 0x02 *\/ */
	  /*   { */
	  /*     NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR - Password (roasted) \n"); */
	  /*     ndpi_int_oscar_add_connection(ndpi_struct, flow); */
	  /*     return; */
	  /*   } */
	  /* CLIENT_NAME */
	  if (get_u_int16_t(packet->payload, 10) == htons(CLIENT_NAME)) /* packet->payload[10] == 0x00 && packet->payload[11] == 0x03 */
	    {
	      NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR - Client Name \n");
	      ndpi_int_oscar_add_connection(ndpi_struct, flow);
	      return;
	    }
	  /* LOGIN_COOKIE */
	  if (get_u_int16_t(packet->payload, 10) == htons(LOGIN_COOKIE) &&
	      get_u_int16_t(packet->payload, 12) == htons(0x0100))
	    {
	      if(get_u_int16_t(packet->payload, packet->payload_packet_len - 5) == htons(MULTICONN_FLAGS)) /* MULTICONN_FLAGS */
		{
		  if(get_u_int16_t(packet->payload, packet->payload_packet_len - 3) == htons(0x0001))
		    if((get_u_int8_t(packet->payload, packet->payload_packet_len - 1) == 0x00) ||
		       (get_u_int8_t(packet->payload, packet->payload_packet_len - 1) == 0x01) ||
		       (get_u_int8_t(packet->payload, packet->payload_packet_len - 1) == 0x03))
		      {
			NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR - Login \n");
			ndpi_int_oscar_add_connection(ndpi_struct, flow);
			return;
		      }
		}
	    }
	  /* MAJOR_VERSION */
	  if (get_u_int16_t(packet->payload, 10) == htons(MAJOR_VERSION))
	    {
	      NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR - Major_Version \n");
	      ndpi_int_oscar_add_connection(ndpi_struct, flow);
	      return;
	    }
	  /* MINOR_VERSION */
	  if (get_u_int16_t(packet->payload, 10) == htons(MINOR_VERSION))
	    {
	      NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR - Minor_Version \n");
	      ndpi_int_oscar_add_connection(ndpi_struct, flow);
	      return;
	    }
	  /* POINT_VERSION */
	  if (get_u_int16_t(packet->payload, 10) == htons(POINT_VERSION))
	    {
	      NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR - Point_Version \n");
	      ndpi_int_oscar_add_connection(ndpi_struct, flow);
	      return;
	    }
	  /* BUILD_NUM */
	  if (get_u_int16_t(packet->payload, 10) == htons(BUILD_NUM))
	    {
	      NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR - Build_Num \n");
	      ndpi_int_oscar_add_connection(ndpi_struct, flow);
	      return;
	    }
	  /* CLIENT_RECONNECT */
	  if (get_u_int16_t(packet->payload, 10) == htons(CLIENT_RECONNECT))
	    {
	      NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR - Client_Reconnect \n");
	      ndpi_int_oscar_add_connection(ndpi_struct, flow);
	      return;
	    }
	}

      /*
	 Messages using the FLAP connection, usually a SNAC message.

	 DATA -> FLAP__DATA_FRAME
	 +-------------------------+
	 + FLAP__Header | 6 byte   +
	 + SNAC__Header | 10 byte  +
	 + snac         |          +
	 +-------------------------+

	 SNAC__Header
	 +----------------------------------------------+
	 + ID           | 4 byte (2 foodgroup + 2 type) +
	 + FLAGS        | 2 byte                        +
	 + requestId    | 4 byte                        +
	 +----------------------------------------------+
      */
      if (channel == DATA)
	{
	  if (packet->payload_packet_len >= 8)
	    family = get_u_int16_t(packet->payload, 6);
	  else
	    family = 0;
	  if (packet->payload_packet_len >= 10)
	    type = get_u_int16_t(packet->payload, 8);
	  else
	    type = 0;
	  if (family == 0 || type == 0)
	  {
	      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_OSCAR);
	      return;
	  }

	  /* Family 0x0001 */
	  if (family == htons(GE_SE_CTL))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      case  (0x0008): break;
	      case  (0x0009): break;
	      case  (0x000a): break;
	      case  (0x000b): break;
	      case  (0x000c): break;
	      case  (0x000d): break;
	      case  (0x000e): break;
	      case  (0x000f): break;
	      case  (0x0010): break;
	      case  (0x0011): break;
	      case  (0x0012): break;
	      case  (0x0013): break;
	      case  (0x0014): break;
	      case  (0x0015): break;
	      case  (0x0016): break;
	      case  (0x0017): break;
	      case  (0x0018): break;
	      case  (0x001e): break;
	      case  (0x001f): break;
	      case  (0x0020): break;
	      case  (0x0021): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0002 */
	  if (family == htons(LOC_SRV))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      case  (0x0008): break;
	      case  (0x0009): break;
	      case  (0x000a): break;
	      case  (0x000b): break;
	      case  (0x000c): break;
	      case  (0x000f): break;
	      case  (0x0010): break;
	      case  (0x0015): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0003 */
	  if (family == htons(BUDDY_LIST))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      case  (0x0008): break;
	      case  (0x0009): break;
	      case  (0x000a): break;
	      case  (0x000b): break;
	      case  (0x000c): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0004 */
	  if (family == htons(IM))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      case  (0x0008): break;
	      case  (0x0009): break;
	      case  (0x000a): break;
	      case  (0x000b): break;
	      case  (0x000c): break;
	      case  (0x0014): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0006 */
	  if (family == htons(IS))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0007 */
	  if (family == htons(ACC_ADM))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      case  (0x0008): break;
	      case  (0x0009): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0008 */
	  if (family == htons(POPUP))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0009 */
	  if (family == htons(PMS))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      case  (0x0008): break;
	      case  (0x0009): break;
	      case  (0x000a): break;
	      case  (0x000b): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x000b */
	  if (family == htons(USS))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x000d */
	  if (family == htons(CHAT_ROOM_SETUP))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      case  (0x0008): break;
	      case  (0x0009): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x000e */
	  if (family == htons(CHAT_ROOM_ACT))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      case  (0x0008): break;
	      case  (0x0009): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x000f */
	  if (family == htons(USER_SRCH))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0010 */
	  if (family == htons(BUDDY_ICON_SERVER))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0013 */
	  if (family == htons(SERVER_STORED_INFO))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      case  (0x0008): break;
	      case  (0x0009): break;
	      case  (0x000a): break;
	      case  (0x000e): break;
	      case  (0x000f): break;
	      case  (0x0011): break;
	      case  (0x0012): break;
	      case  (0x0014): break;
	      case  (0x0015): break;
	      case  (0x0016): break;
	      case  (0x0018): break;
	      case  (0x001a): break;
	      case  (0x001b): break;
	      case  (0x001c): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0015 */
	  if (family == htons(ICQ))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0017 */
	  if (family == htons(INIT_AUTH))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      case  (0x0004): break;
	      case  (0x0005): break;
	      case  (0x0006): break;
	      case  (0x0007): break;
	      case  (0x000a): break;
	      case  (0x000b): break;
	      default: excluded = 1;
	      }
	    }
	  /* Family 0x0018 */
	  if (family == htons(EMAIL))
	    {
	      /* TODO */
	    }
	  /* Family 0x0085 */
	  if (family == htons(IS_EXT))
	    {
	      switch (type) {

	      case  (0x0001): break;
	      case  (0x0002): break;
	      case  (0x0003): break;
	      default: excluded = 1;
	      }
	    }

	  if(excluded == 1)
	    {
	      NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "exclude oscar.\n");
	      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_OSCAR);
	    }

	  /* flag */
	  if (packet->payload_packet_len >= 12)
	  {
	    flag = get_u_int16_t(packet->payload, 10);
	    if (flag == htons(0x0000)|| flag == htons(0x8000) || flag == htons(0x0001))
	      {
	        if (packet->payload_packet_len >= 16)
		{
		  /* request ID */
		  req_ID = get_u_int32_t(packet->payload, 12);
		  if((req_ID <= ((u_int32_t)-1)))
		    {
		      NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR Detected \n");
		      ndpi_int_oscar_add_connection(ndpi_struct, flow);
		      return;
		    }
		}
	      }
	  }
	}
      /*
	 ERROR -> FLAP__ERROR_CHANNEL_0x03
	 A FLAP error - rare
      */
      if (channel == O_ERROR)
	{
	  NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR Detected - Error frame \n");
	  ndpi_int_oscar_add_connection(ndpi_struct, flow);
	  return;
	}
      /*
	 Close down the FLAP connection gracefully.
	 SIGNOFF: FLAP__SIGNOFF_CHANNEL_0x04
      */
      if (channel == SIGNOFF)
	{
	  NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR Detected - Signoff frame \n");
	  ndpi_int_oscar_add_connection(ndpi_struct, flow);
	  return;
	}
      /*
	 Send a heartbeat to server to help keep connection open.
	 KEEP_ALIVE: FLAP__KEEP_ALIVE_CHANNEL_0x05
      */
      if (channel == KEEP_ALIVE)
	{
	  NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR Detected - Keep Alive frame \n");
	  ndpi_int_oscar_add_connection(ndpi_struct, flow);
	  return;
	}
    }


  /* detect http connections */
  if (packet->payload_packet_len >= 18) {
    if ((packet->payload[0] == 'P') && (memcmp(packet->payload, "POST /photo/upload", 18) == 0)) {
      NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);
      if (packet->host_line.len >= 18 && packet->host_line.ptr != NULL) {
	if (memcmp(packet->host_line.ptr, "lifestream.aol.com", 18) == 0) {
	  NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG,
		   "OSCAR over HTTP found, POST method\n");
	  ndpi_int_oscar_add_connection(ndpi_struct, flow);
	  return;
	}
      }
    }
  }
  if (packet->payload_packet_len > 40) {
    if ((packet->payload[0] == 'G') && (memcmp(packet->payload, "GET /", 5) == 0)) {
      if ((memcmp(&packet->payload[5], "aim/fetchEvents?aimsid=", 23) == 0) ||
	  (memcmp(&packet->payload[5], "aim/startSession?", 17) == 0) ||
	  (memcmp(&packet->payload[5], "aim/gromit/aim_express", 22) == 0) ||
	  (memcmp(&packet->payload[5], "b/ss/aolwpaim", 13) == 0) ||
	  (memcmp(&packet->payload[5], "hss/storage/aimtmpshare", 23) == 0)) {
	NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR over HTTP found, GET /aim/\n");
	ndpi_int_oscar_add_connection(ndpi_struct, flow);
	return;
      }

      if ((memcmp(&packet->payload[5], "aim", 3) == 0) || (memcmp(&packet->payload[5], "im", 2) == 0)) {
	NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);
	if (packet->user_agent_line.len > 15 && packet->user_agent_line.ptr != NULL &&
	    ((memcmp(packet->user_agent_line.ptr, "mobileAIM/", 10) == 0) ||
	     (memcmp(packet->user_agent_line.ptr, "ICQ/", 4) == 0) ||
	     (memcmp(packet->user_agent_line.ptr, "mobileICQ/", 10) == 0) ||
	     (memcmp(packet->user_agent_line.ptr, "AIM%20Free/", NDPI_STATICSTRING_LEN("AIM%20Free/")) == 0) ||
	     (memcmp(packet->user_agent_line.ptr, "AIM/", 4) == 0))) {
	  NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR over HTTP found\n");
	  ndpi_int_oscar_add_connection(ndpi_struct, flow);
	  return;
	}
      }
      NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);
      if (packet->referer_line.ptr != NULL && packet->referer_line.len >= 22) {

	if (memcmp(&packet->referer_line.ptr[packet->referer_line.len - NDPI_STATICSTRING_LEN("WidgetMain.swf")],
		   "WidgetMain.swf", NDPI_STATICSTRING_LEN("WidgetMain.swf")) == 0) {
	  u_int16_t i;
	  for (i = 0; i < (packet->referer_line.len - 22); i++) {
	    if (packet->referer_line.ptr[i] == 'a') {
	      if (memcmp(&packet->referer_line.ptr[i + 1], "im/gromit/aim_express", 21) == 0) {
		NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG,
			 "OSCAR over HTTP found : aim/gromit/aim_express\n");
		ndpi_int_oscar_add_connection(ndpi_struct, flow);
		return;
	      }
	    }
	  }
	}
      }
    }
    if (memcmp(packet->payload, "CONNECT ", 8) == 0) {
      if (memcmp(packet->payload, "CONNECT login.icq.com:443 HTTP/1.", 33) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR ICQ-HTTP FOUND\n");
	ndpi_int_oscar_add_connection(ndpi_struct, flow);
	return;
      }
      if (memcmp(packet->payload, "CONNECT login.oscar.aol.com:5190 HTTP/1.", 40) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR AIM-HTTP FOUND\n");
	ndpi_int_oscar_add_connection(ndpi_struct, flow);
	return;
      }

    }
  }

  if (packet->payload_packet_len > 43
      && memcmp(packet->payload, "GET http://http.proxy.icq.com/hello HTTP/1.", 43) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR ICQ-HTTP PROXY FOUND\n");
    ndpi_int_oscar_add_connection(ndpi_struct, flow);
    return;
  }

  if (packet->payload_packet_len > 46
      && memcmp(packet->payload, "GET http://aimhttp.oscar.aol.com/hello HTTP/1.", 46) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR AIM-HTTP PROXY FOUND\n");
    ndpi_int_oscar_add_connection(ndpi_struct, flow);
    return;
  }

  if (packet->payload_packet_len > 5 && get_u_int32_t(packet->payload, 0) == htonl(0x05010003)) {
    NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "Maybe OSCAR Picturetransfer\n");
    return;
  }

  if (packet->payload_packet_len == 10 && get_u_int32_t(packet->payload, 0) == htonl(0x05000001) &&
      get_u_int32_t(packet->payload, 4) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "Maybe OSCAR Picturetransfer\n");
    return;
  }

  if (packet->payload_packet_len >= 70 &&
      memcmp(&packet->payload[packet->payload_packet_len - 26],
	     "\x67\x00\x65\x00\x74\x00\x43\x00\x61\x00\x74\x00\x61\x00\x6c\x00\x6f\x00\x67", 19) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR PICTURE TRANSFER\n");
    ndpi_int_oscar_add_connection(ndpi_struct, flow);
    return;
  }

  if (NDPI_SRC_OR_DST_HAS_PROTOCOL(src, dst, NDPI_PROTOCOL_OSCAR) != 0) {

    if (flow->packet_counter == 1
	&&
	((packet->payload_packet_len == 9
	  && memcmp(packet->payload, "\x00\x09\x00\x00\x83\x01\xc0\x00\x00", 9) == 0)
	 || (packet->payload_packet_len == 13
	     && (memcmp(packet->payload, "\x00\x0d\x00\x87\x01\xc0", 6) == 0
		 || memcmp(packet->payload, "\x00\x0d\x00\x87\x01\xc1", 6) == 0)))) {
      flow->oscar_video_voice = 1;
    }
    if (flow->oscar_video_voice && ntohs(get_u_int16_t(packet->payload, 0)) == packet->payload_packet_len
	&& packet->payload[2] == 0x00 && packet->payload[3] == 0x00) {
    }

    if (packet->payload_packet_len >= 70 && ntohs(get_u_int16_t(packet->payload, 4)) == packet->payload_packet_len) {
      if (memcmp(packet->payload, "OFT", 3) == 0 &&
	  ((packet->payload[3] == '3' && ((memcmp(&packet->payload[4], "\x01\x00\x01\x01", 4) == 0)
					  || (memcmp(&packet->payload[6], "\x01\x01\x00", 3) == 0)))
	   || (packet->payload[3] == '2' && ((memcmp(&packet->payload[6], "\x01\x01", 2)
					      == 0)
					     )))) {
	// FILE TRANSFER PATTERN:: OFT3 or OFT2
	NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR FILE TRANSFER\n");
	ndpi_int_oscar_add_connection(ndpi_struct, flow);
	return;
      }

      if (memcmp(packet->payload, "ODC2", 4) == 0 && memcmp(&packet->payload[6], "\x00\x01\x00\x06", 4) == 0) {
	//PICTURE TRANSFER PATTERN EXMAPLE::
	//4f 44 43 32 00 4c 00 01 00 06 00 00 00 00 00 00  ODC2.L..........
	NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR PICTURE TRANSFER\n");
	ndpi_int_oscar_add_connection(ndpi_struct, flow);
	return;
      }
    }
    if (packet->payload_packet_len > 40 && (memcmp(&packet->payload[2], "\x04\x4a\x00", 3) == 0)
	&& (memcmp(&packet->payload[6], "\x00\x00", 2) == 0)
	&& packet->payload[packet->payload_packet_len - 15] == 'F'
	&& packet->payload[packet->payload_packet_len - 12] == 'L'
	&& (memcmp(&packet->payload[packet->payload_packet_len - 6], "DEST", 4) == 0)
	&& (memcmp(&packet->payload[packet->payload_packet_len - 2], "\x00\x00", 2) == 0)) {
      NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR PICTURE TRANSFER\n");
      ndpi_int_oscar_add_connection(ndpi_struct, flow);
      if (ntohs(packet->tcp->dest) == 443 || ntohs(packet->tcp->source) == 443) {
	flow->oscar_ssl_voice_stage = 1;
      }
      return;

    }
  }
  if (flow->packet_counter < 3 && packet->payload_packet_len > 11 && (memcmp(packet->payload, "\x00\x37\x04\x4a", 4)
								      || memcmp(packet->payload, "\x00\x0a\x04\x4a",
										4))) {
    return;
  }


  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_OSCAR) {
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_OSCAR);
    return;
  }
}

void ndpi_search_oscar(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  if (packet->tcp != NULL) {
    NDPI_LOG(NDPI_PROTOCOL_OSCAR, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR :: TCP\n");
    ndpi_search_oscar_tcp_connect(ndpi_struct, flow);
  }
}


void init_oscar_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Oscar", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_OSCAR,
				      ndpi_search_oscar,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
