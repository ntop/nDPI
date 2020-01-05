/*
 * dhcp.c
 *
 * Copyright (C) 2016-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DHCP

#include "ndpi_api.h"

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

  NDPI_LOG_DBG(ndpi_struct, "search DHCP\n");

  /* this detection also works for asymmetric dhcp traffic */

  /*check standard DHCP 0.0.0.0:68 -> 255.255.255.255:67 */
  if(packet->udp) {
    dhcp_packet_t *dhcp = (dhcp_packet_t*)packet->payload;

    if((packet->payload_packet_len >= 244 /* 244 is the offset of options[0] in dhcp_packet_t */)
       && (packet->udp->source == htons(67) || packet->udp->source == htons(68))
       && (packet->udp->dest == htons(67) || packet->udp->dest == htons(68))
       && (dhcp->magic == htonl(DHCP_OPTION_MAGIC_NUMBER))) {
      u_int i = 0, foundValidMsgType = 0;

      u_int dhcp_options_size = ndpi_min(DHCP_VEND_LEN /* maximum size of options in dhcp_packet_t */,
					 packet->payload_packet_len - 244);

      while(i + 1 /* for the len */ < dhcp_options_size) {
	u_int8_t id  = dhcp->options[i];

	if(id == 0xFF)
	  break;
	else {
	  /* Prevent malformed packets to cause out-of-bounds accesses */
	  u_int8_t len = ndpi_min(dhcp->options[i+1] /* len as found in the packet */,
				  dhcp_options_size - (i+2) /* 1 for the type and 1 for the value */);

	  if(len == 0) break;

#ifdef DHCP_DEBUG
	  NDPI_LOG_DBG2(ndpi_struct, "[DHCP] Id=%d [len=%d]\n", id, len);
#endif

	  if(id == 53 /* DHCP Message Type */) {
	    u_int8_t msg_type = dhcp->options[i+2];

	    if(msg_type <= 8) foundValidMsgType = 1;
	  } else if(id == 55 /* Parameter Request List / Fingerprint */) {
	    u_int idx, offset = 0;
	    
	    for(idx = 0; idx < len && offset < sizeof(flow->protos.dhcp.fingerprint) - 2; idx++) {
	      int rc = snprintf((char*)&flow->protos.dhcp.fingerprint[offset],
				sizeof(flow->protos.dhcp.fingerprint) - offset,
				"%s%u", (idx > 0) ? "," : "",
				(unsigned int)dhcp->options[i+2+idx] & 0xFF);
	      
	      if(rc < 0) break; else offset += rc;
	    }
	    
	    flow->protos.dhcp.fingerprint[sizeof(flow->protos.dhcp.fingerprint) - 1] = '\0';	    
	  } else if(id == 60 /* Class Identifier */) {
	    char *name = (char*)&dhcp->options[i+2];
	    int j = 0;
	    
	    j = ndpi_min(len, sizeof(flow->protos.dhcp.class_ident)-1);
	    strncpy((char*)flow->protos.dhcp.class_ident, name, j);
	    flow->protos.dhcp.class_ident[j] = '\0';
	  } else if(id == 12 /* Host Name */) {
	    char *name = (char*)&dhcp->options[i+2];
	    int j = 0;
	    
#ifdef DHCP_DEBUG
	    NDPI_LOG_DBG2(ndpi_struct, "[DHCP] '%.*s'\n",name,len);
	      //	    while(j < len) { printf( "%c", name[j]); j++; }; printf("\n");
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
	NDPI_LOG_INFO(ndpi_struct, "found DHCP\n");
	ndpi_int_dhcp_add_connection(ndpi_struct, flow);
      }
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
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
