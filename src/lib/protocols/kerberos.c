/*
 * kerberos.c
 *
 * Copyright (C) 2011-19 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_KERBEROS

#include "ndpi_api.h"

/* #define KERBEROS_DEBUG 1 */

static void ndpi_int_kerberos_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					     struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_KERBEROS, NDPI_PROTOCOL_UNKNOWN);
  NDPI_LOG_DBG(ndpi_struct, "trace KERBEROS\n");
}

/* ************************************************* */

void ndpi_search_kerberos(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search KERBEROS\n");

  /* I have observed 0a,0c,0d,0e at packet->payload[19/21], maybe there are other possibilities */
  if(packet->payload_packet_len >= 4) {
    u_int32_t kerberos_len = ntohl(get_u_int32_t(packet->payload, 0));
    u_int32_t expected_len = packet->payload_packet_len - 4;

    if(kerberos_len < 1514) {
      /*
	Kerberos packets might be too long for a TCP packet
	so it could be split across two packets. Instead of
	rebuilding the stream we use a heuristic approach
      */
      if(kerberos_len >= expected_len) {
	if(packet->payload_packet_len > 128) {
	  u_int16_t koffset;

	  if(packet->payload[14] == 0x05) /* PVNO */
	    koffset = 19;
	  else
	    koffset = 21;

	  if((packet->payload[koffset] == 0x0a || packet->payload[koffset] == 0x0c || packet->payload[koffset] == 0x0d || packet->payload[koffset] == 0x0e)) {
#ifdef KERBEROS_DEBUG
	    printf("[Kerberos] Packet found\n");
#endif

	    if(packet->payload[koffset] == 0x0a) /* AS-REQ */ {
	      u_int16_t koffsetp, pad_data_len, body_offset;
	      
	      koffsetp = koffset + 4;
	      pad_data_len = packet->payload[koffsetp];	      
	      body_offset  = pad_data_len + koffsetp;

	      if(body_offset < packet->payload_packet_len) {
		u_int name_offset = body_offset + 30;

		if(name_offset < packet->payload_packet_len) {
		  u_int cname_len = packet->payload[name_offset];

		  if((cname_len+name_offset) < packet->payload_packet_len) {
		    u_int realm_len, realm_offset = cname_len + name_offset + 4, i;
		    char cname_str[24];

		    if(cname_len > sizeof(cname_str)-1)
		      cname_len = sizeof(cname_str)-1;

		    strncpy(cname_str, (char*)&packet->payload[name_offset+1], cname_len);
		    cname_str[cname_len] = '\0';
		    for(i=0; i<cname_len; i++) cname_str[i] = tolower(cname_str[i]);

#ifdef KERBEROS_DEBUG
		    printf("[Kerberos Cname][len: %u][%s]\n", cname_len, cname_str);
#endif

		    /* if cname does not end with a $ then it's a username */
		    if(cname_len && cname_str[cname_len-1] == '$') {
		      cname_str[cname_len-1] = '\0';
		      snprintf(flow->protos.kerberos.hostname, sizeof(flow->protos.kerberos.hostname), "%s", cname_str);
		    } else
		      snprintf(flow->protos.kerberos.username, sizeof(flow->protos.kerberos.username), "%s", cname_str);

		    realm_len = packet->payload[realm_offset];

		    if((realm_offset+realm_len) < packet->payload_packet_len) {
		      char realm_str[24];

		      if(realm_len > sizeof(realm_str)-1)
			realm_len = sizeof(realm_str);

		      strncpy(realm_str, (char*)&packet->payload[realm_offset+1], realm_len);
		      realm_str[realm_len] = '\0';
		      for(i=0; i<realm_len; i++) realm_str[i] = tolower(realm_str[i]);

#ifdef KERBEROS_DEBUG
		      printf("[Kerberos Realm][len: %u][%s]\n", realm_len, realm_str);
#endif
		      snprintf(flow->protos.kerberos.domain, sizeof(flow->protos.kerberos.domain), "%s", realm_str);
		    }
		  }
		}
	      }
	    } else if(packet->payload[koffset] == 0x0c) /* TGS-REQ */ {
	      u_int16_t koffsetp, pad_data_len, body_offset;

	      koffsetp = koffset + 3;
	      pad_data_len = ntohs(*((u_int16_t*)&packet->payload[koffsetp]));
	      body_offset = pad_data_len + koffsetp + 4;

	      if(body_offset < packet->payload_packet_len) {
		u_int name_offset = body_offset + 14;

		if(name_offset < packet->payload_packet_len) {
		  u_int realm_len = packet->payload[name_offset];

		  if((realm_len+name_offset) < packet->payload_packet_len) {
		    u_int i;
		    char realm_str[24];

		    if(realm_len > sizeof(realm_str)-1)
		      realm_len = sizeof(realm_str)-1;

		    strncpy(realm_str, (char*)&packet->payload[name_offset+1], realm_len);
		    realm_str[realm_len] = '\0';
		    for(i=0; i<realm_len; i++) realm_str[i] = tolower(realm_str[i]);

#ifdef KERBEROS_DEBUG
		    printf("[Kerberos Realm][len: %u][%s]\n", realm_len, realm_str);
#endif
		    snprintf(flow->protos.kerberos.domain, sizeof(flow->protos.kerberos.domain), "%s", realm_str);
		  }
		}
	      }

	      /* We set the protocol in the response */
	      return;
	    } else if(packet->payload[koffset] == 0x0d) /* TGS-RES */ {
	      u_int16_t koffsetp, pad_data_len, cname_offset;

	      koffsetp = koffset + 4;
	      pad_data_len = packet->payload[koffsetp];
	      /* Skip realm already filled in request */
	      cname_offset = pad_data_len + koffsetp + 15;

	      if(cname_offset < packet->payload_packet_len) {
		u_int8_t cname_len = packet->payload[cname_offset];

		if((cname_offset+cname_offset) < packet->payload_packet_len) {
		  char cname_str[24];
		  u_int i;
		  
		  if(cname_len > sizeof(cname_str)-1)
		    cname_len = sizeof(cname_str)-1;
		  
		  strncpy(cname_str, (char*)&packet->payload[cname_offset+1], cname_len);
		  cname_str[cname_len] = '\0';
		  for(i=0; i<cname_len; i++) cname_str[i] = tolower(cname_str[i]);
		  
#ifdef KERBEROS_DEBUG
		  printf("[Kerberos Cname][len: %u][%s]\n", cname_len, cname_str);
#endif
		  
		  if(cname_len && cname_str[cname_len-1] == '$') {
		    cname_str[cname_len-1] = '\0';
		    snprintf(flow->protos.kerberos.hostname, sizeof(flow->protos.kerberos.hostname), "%s", cname_str);
		  } else
		    snprintf(flow->protos.kerberos.username, sizeof(flow->protos.kerberos.username), "%s", cname_str);

		  ndpi_int_kerberos_add_connection(ndpi_struct, flow);
		}
	      }
	    }
	    
	    return;
	  }

	  if(packet->payload_packet_len > 21 &&
	     packet->payload[16] == 0x05 &&
	     (packet->payload[21] == 0x0a ||
	      packet->payload[21] == 0x0c || packet->payload[21] == 0x0d || packet->payload[21] == 0x0e)) {
	    ndpi_int_kerberos_add_connection(ndpi_struct, flow);
	    return;
	  }
	}
      }
    } else {
      if(flow->protos.kerberos.domain[0] != '\0')
	return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_kerberos_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			     u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("Kerberos", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_KERBEROS,
				      ndpi_search_kerberos,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
