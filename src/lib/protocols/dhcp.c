/*
 * dhcp.c
 *
 * Copyright (C) 2016 - ntop.org
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

#ifdef NDPI_PROTOCOL_DHCP

/* freeradius/src/lib/dhcp.c */
#define DHCP_CHADDR_LEN	16
#define DHCP_SNAME_LEN	64
#define DHCP_FILE_LEN	128
#define DHCP_VEND_LEN	308
#define DHCP_OPTION_MAGIC_NUMBER 	0x63825363


typedef struct {
  uint8_t	msgType;
  uint8_t	htype;
  uint8_t	hlen;
  uint8_t	hops;
  uint32_t	xid;/* 4 */
  uint16_t	secs;/* 8 */
  uint16_t	flags;
  uint32_t	ciaddr;/* 12 */
  uint32_t	yiaddr;/* 16 */
  uint32_t	siaddr;/* 20 */
  uint32_t	giaddr;/* 24 */
  uint8_t	chaddr[DHCP_CHADDR_LEN]; /* 28 */
  uint8_t	sname[DHCP_SNAME_LEN]; /* 44 */
  uint8_t	file[DHCP_FILE_LEN]; /* 108 */
  uint32_t	magic; /* 236 */
  uint8_t	options[DHCP_VEND_LEN];
} dhcp_packet_t;


static void ndpi_int_dhcp_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DHCP, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_dhcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  /* this detection also works for asymmetric dhcp traffic */

  /*check standard DHCP 0.0.0.0:68 -> 255.255.255.255:67 */
  if(packet->udp) {
    dhcp_packet_t *dhcp = (dhcp_packet_t*)packet->payload;

    if((packet->payload_packet_len >= 244)
       && (packet->udp->source == htons(67) || packet->udp->source == htons(68))
       && (packet->udp->dest == htons(67) || packet->udp->dest == htons(68))
       && (dhcp->magic == htonl(DHCP_OPTION_MAGIC_NUMBER))) {
      int i = 0, foundValidMsgType = 0;

      while(i < DHCP_VEND_LEN) {
	u_int8_t id  = dhcp->options[i];
	if(id == 0xFF) break;
	else {
	  u_int8_t len = dhcp->options[i+1];
	  
	  if(len == 0) break;
	  
#ifdef DHCP_DEBUG
	  printf("[DHCP] Id=%d [len=%d]\n", id, len);
#endif
	  
	  if(id == 53 /* DHCP Message Type */) {
	    u_int8_t msg_type = dhcp->options[i+2];
	    
	    if(msg_type <= 8) foundValidMsgType = 1;
	  } else if(id == 12 /* Host Name */) {
	    char *name = (char*)&dhcp->options[i+2];
	    int j = 0;
	    
#ifdef DHCP_DEBUG
	    printf("[DHCP] ");
	    while(j < len) { printf("%c", name[j]); j++; }
	    printf("\n");
#endif
	    j = ndpi_min(len, sizeof(flow->host_server_name)-1);
	    strncpy((char*)flow->host_server_name, name, j);
	    flow->host_server_name[j] = '\0';
	  }
	  i += len + 2;
	}
      }

      //get_u_int16_t(packet->payload, 240) == htons(0x3501)) {

      if(foundValidMsgType) {
	NDPI_LOG(NDPI_PROTOCOL_DHCP, ndpi_struct, NDPI_LOG_DEBUG, "DHCP found\n");
	ndpi_int_dhcp_add_connection(ndpi_struct, flow);
      }
      return;
    }
  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DHCP);
}


void init_dhcp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("DHCP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DHCP,
				      ndpi_search_dhcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

#endif
