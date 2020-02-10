/*
 * kerberos.c
 *
 * Copyright (C) 2011-20 - ntop.org
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

#define KERBEROS_PORT 88

static void ndpi_int_kerberos_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					     struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_KERBEROS, NDPI_PROTOCOL_UNKNOWN);
  NDPI_LOG_DBG(ndpi_struct, "trace KERBEROS\n");
}

/* ************************************************* */

void ndpi_search_kerberos(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t sport = packet->tcp ? ntohs(packet->tcp->source) : ntohs(packet->udp->source);
  u_int16_t dport = packet->tcp ? ntohs(packet->tcp->dest) : ntohs(packet->udp->dest);

  if((sport != KERBEROS_PORT) && (dport != KERBEROS_PORT)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  
  NDPI_LOG_DBG(ndpi_struct, "search KERBEROS\n");

#ifdef KERBEROS_DEBUG
  printf("\n[Kerberos] Process packet [len: %u]\n", packet->payload_packet_len);
#endif
    
  if(flow->kerberos_buf.pktbuf != NULL) {
    u_int missing = flow->kerberos_buf.pktbuf_maxlen - flow->kerberos_buf.pktbuf_currlen;

    if(packet->payload_packet_len <= missing) {
      memcpy(&flow->kerberos_buf.pktbuf[flow->kerberos_buf.pktbuf_currlen], packet->payload, packet->payload_packet_len);
      flow->kerberos_buf.pktbuf_currlen += packet->payload_packet_len;

      if(flow->kerberos_buf.pktbuf_currlen == flow->kerberos_buf.pktbuf_maxlen) {
	packet->payload = (u_int8_t *)flow->kerberos_buf.pktbuf;
	packet->payload_packet_len = flow->kerberos_buf.pktbuf_currlen;
#ifdef KERBEROS_DEBUG
	printf("[Kerberos] Packet is now full: processing\n");
#endif
      } else {
#ifdef KERBEROS_DEBUG
	printf("[Kerberos] Missing %u bytes: skipping\n",
	       flow->kerberos_buf.pktbuf_maxlen - flow->kerberos_buf.pktbuf_currlen);
#endif

	return;
      }
    }
  }

  /* I have observed 0a,0c,0d,0e at packet->payload[19/21], maybe there are other possibilities */
  if(packet->payload_packet_len >= 4) {
    u_int32_t kerberos_len, expected_len;
    u_int16_t base_offset = 0;

    if(packet->tcp) {
      kerberos_len = ntohl(get_u_int32_t(packet->payload, 0)),
	expected_len = packet->payload_packet_len - 4;
      base_offset = 4;
    } else
      base_offset = 0, kerberos_len = expected_len = packet->payload_packet_len;

#ifdef KERBEROS_DEBUG
    printf("[Kerberos] [Kerberos len: %u][expected_len: %u]\n", kerberos_len, expected_len);
#endif

    if(kerberos_len < 12000) {
      /*
	Kerberos packets might be too long for a TCP packet
	so it could be split across two packets. Instead of
	rebuilding the stream we use a heuristic approach
      */
      if(kerberos_len > expected_len) {
	if(packet->tcp) {
	  if(flow->kerberos_buf.pktbuf == NULL) {
	    flow->kerberos_buf.pktbuf = (char*)ndpi_malloc(kerberos_len+4);

	    if(flow->kerberos_buf.pktbuf != NULL) {
	      flow->kerberos_buf.pktbuf_maxlen = kerberos_len+4;	      
#ifdef KERBEROS_DEBUG
	      printf("[Kerberos] Allocated %u bytes\n", flow->kerberos_buf.pktbuf_maxlen);
#endif	      
	    }
	  }
	  
	  if(flow->kerberos_buf.pktbuf != NULL) {
	    if(packet->payload_packet_len <= flow->kerberos_buf.pktbuf_maxlen) {
	      memcpy(flow->kerberos_buf.pktbuf, packet->payload, packet->payload_packet_len);
	      flow->kerberos_buf.pktbuf_currlen = packet->payload_packet_len;
	    }
	  }
	}
	
	return;
      } else if(kerberos_len == expected_len) {
	if(packet->payload_packet_len > 128) {
	  u_int16_t koffset, i;

	  for(i=8; i<16; i++)
	    if((packet->payload[base_offset+i] == 0x03)
	       && (packet->payload[base_offset+i+1] == 0x02)
	       && (packet->payload[base_offset+i+2] == 0x01)
	       && (packet->payload[base_offset+i+3] != 0x05)
	       )
	      break;

	  koffset = base_offset + i + 3;

#ifdef KERBEROS_DEBUG
	  printf("[Kerberos] [msg-type: 0x%02X/%u][koffset: %u]\n",
		 packet->payload[koffset], packet->payload[koffset], koffset);
#endif

	  if(((packet->payload[koffset] == 0x0A)
	      || (packet->payload[koffset] == 0x0C)
	      || (packet->payload[koffset] == 0x0D)
	      || (packet->payload[koffset] == 0x0E))) {
	    u_int16_t koffsetp, body_offset, pad_len;
	    u_int8_t msg_type = packet->payload[koffset];

#ifdef KERBEROS_DEBUG
	    printf("[Kerberos] Packet found 0x%02X/%u\n", msg_type, msg_type);
#endif
	    if(msg_type != 0x0d) /* TGS-REP */ {
	      /* Process only on requests */
	      if(packet->payload[koffset+1] == 0xA3) {
		if(packet->payload[koffset+3] == 0x30)
		  pad_len = packet->payload[koffset+4];
		else {
		  /* Long pad */
		  pad_len = packet->payload[koffset+2];
		  for(i=3; i<10; i++) if(packet->payload[koffset+i] == pad_len) break;

		  pad_len = (packet->payload[koffset+i+1] << 8) + packet->payload[koffset+i+2];
		  koffset += i-2;
		}
	      } else
		pad_len = 0;

#ifdef KERBEROS_DEBUG
	      printf("pad_len=0x%02X/%u\n", pad_len, pad_len);
#endif

	      if(pad_len > 0) {
		koffsetp = koffset + 2;
		for(i=0; i<4; i++) if(packet->payload[koffsetp] != 0x30) koffsetp++; /* ASN.1 */
#ifdef KERBEROS_DEBUG
		printf("koffsetp=%u [%02X %02X] [byte 0 must be 0x30]\n", koffsetp, packet->payload[koffsetp], packet->payload[koffsetp+1]);
#endif
	      } else
		koffsetp = koffset;

	      body_offset = koffsetp + 1 + pad_len;

	      for(i=0; i<10; i++) if(packet->payload[body_offset] != 0x05) body_offset++; /* ASN.1 */
#ifdef KERBEROS_DEBUG
	      printf("body_offset=%u [%02X %02X] [byte 0 must be 0x05]\n", body_offset, packet->payload[body_offset], packet->payload[body_offset+1]);
#endif
	    }
	    
	    if(msg_type == 0x0A) /* AS-REQ */ {
#ifdef KERBEROS_DEBUG
	      printf("[Kerberos] Processing AS-REQ\n");
#endif


	      if(body_offset < packet->payload_packet_len) {
		u_int16_t name_offset;

		name_offset = body_offset + 13;
		for(i=0; i<20; i++) if(packet->payload[name_offset] != 0x1b) name_offset++; /* ASN.1 */

#ifdef KERBEROS_DEBUG
		printf("name_offset=%u [%02X %02X] [byte 0 must be 0x1b]\n", name_offset, packet->payload[name_offset], packet->payload[name_offset+1]);
#endif

		if(name_offset < packet->payload_packet_len) {
		  u_int cname_len;

		  name_offset += 1;
		  if(packet->payload[name_offset+1] < ' ') /* Isn't printable ? */
		    name_offset++;

		  if(packet->payload[name_offset+1] == 0x1b)
		    name_offset += 2;
		  
		  cname_len = packet->payload[name_offset];

		  if((cname_len+name_offset) < packet->payload_packet_len) {
		    u_int realm_len, realm_offset;
		    char cname_str[48];
		    u_int8_t num_cname = 0;

		    while(++num_cname <= 2) {
		      if(cname_len > sizeof(cname_str)-1)
			cname_len = sizeof(cname_str)-1;

		      strncpy(cname_str, (char*)&packet->payload[name_offset+1], cname_len);
		      cname_str[cname_len] = '\0';
		      for(i=0; i<cname_len; i++) cname_str[i] = tolower(cname_str[i]);

#ifdef KERBEROS_DEBUG
		      printf("[AS-REQ][s/dport: %u/%u][Kerberos Cname][len: %u][%s]\n", sport, dport, cname_len, cname_str);
#endif

		      if(((strcmp(cname_str, "host") == 0) || (strcmp(cname_str, "ldap") == 0)) && (packet->payload[name_offset+1+cname_len] == 0x1b)) {
			name_offset += cname_len + 2;
			cname_len = packet->payload[name_offset];
		      } else
			break;
		    }

		    realm_offset = cname_len + name_offset + 3;

		    /* if cname does not end with a $ then it's a username */
		    if(cname_len && cname_str[cname_len-1] == '$') {
		      cname_str[cname_len-1] = '\0';
		      snprintf(flow->protos.kerberos.hostname, sizeof(flow->protos.kerberos.hostname), "%s", cname_str);
		    } else
		      snprintf(flow->protos.kerberos.username, sizeof(flow->protos.kerberos.username), "%s", cname_str);

		    for(i=0; i<14; i++) if(packet->payload[realm_offset] != 0x1b) realm_offset++; /* ASN.1 */
#ifdef KERBEROS_DEBUG
		    printf("realm_offset=%u [%02X %02X] [byte 0 must be 0x1b]\n", realm_offset, packet->payload[realm_offset], packet->payload[realm_offset+1]);
#endif
		    realm_offset += 1;
		    //if(num_cname == 2) realm_offset++;
		    realm_len = packet->payload[realm_offset];

		    if((realm_offset+realm_len) < packet->payload_packet_len) {
		      char realm_str[48];

		      if(realm_len > sizeof(realm_str)-1)
			realm_len = sizeof(realm_str)-1;

		      realm_offset += 1;

		      strncpy(realm_str, (char*)&packet->payload[realm_offset], realm_len);
		      realm_str[realm_len] = '\0';
		      for(i=0; i<realm_len; i++) realm_str[i] = tolower(realm_str[i]);

#ifdef KERBEROS_DEBUG
		      printf("[AS-REQ][Kerberos Realm][len: %u][%s]\n", realm_len, realm_str);
#endif
		      snprintf(flow->protos.kerberos.domain, sizeof(flow->protos.kerberos.domain), "%s", realm_str);
		    }
		  }
		}
	      } 
	    } else if(msg_type == 0x0c) /* TGS-REQ */ {
#ifdef KERBEROS_DEBUG
	      printf("[Kerberos] Processing TGS-REQ\n");
#endif

	      if(body_offset < packet->payload_packet_len) {
		u_int name_offset, padding_offset = body_offset + 4;

		name_offset = padding_offset;
		for(i=0; i<14; i++) if(packet->payload[name_offset] != 0x1b) name_offset++; /* ASN.1 */

#ifdef KERBEROS_DEBUG
		printf("name_offset=%u [%02X %02X] [byte 0 must be 0x1b]\n", name_offset, packet->payload[name_offset], packet->payload[name_offset+1]);
#endif

		if(name_offset < packet->payload_packet_len) {
		  u_int realm_len;

		  name_offset++;
		  realm_len = packet->payload[name_offset];

		  if((realm_len+name_offset) < packet->payload_packet_len) {
		    char realm_str[48];

		    if(realm_len > sizeof(realm_str)-1)
		      realm_len = sizeof(realm_str)-1;

		    name_offset += 1;

		    strncpy(realm_str, (char*)&packet->payload[name_offset], realm_len);
		    realm_str[realm_len] = '\0';
		    for(i=0; i<realm_len; i++) realm_str[i] = tolower(realm_str[i]);

#ifdef KERBEROS_DEBUG
		    printf("[TGS-REQ][s/dport: %u/%u][Kerberos Realm][len: %u][%s]\n", sport, dport, realm_len, realm_str);
#endif
		    snprintf(flow->protos.kerberos.domain, sizeof(flow->protos.kerberos.domain), "%s", realm_str);

		    /* If necessary we can decode sname */

		    if(flow->kerberos_buf.pktbuf) ndpi_free(flow->kerberos_buf.pktbuf);
		    flow->kerberos_buf.pktbuf = NULL;
		  }
		}
	      }

	      if(packet->udp)
		ndpi_int_kerberos_add_connection(ndpi_struct, flow);

	      /* We set the protocol in the response */
	      if(flow->kerberos_buf.pktbuf != NULL) {
		ndpi_free(flow->kerberos_buf.pktbuf);
		flow->kerberos_buf.pktbuf = NULL;
	      }
	      
	      return;
	    } else if(msg_type == 0x0d) /* TGS-REP */ {
	      u_int16_t pad_data_len, cname_offset;
	      
#ifdef KERBEROS_DEBUG
	      printf("[Kerberos] Processing TGS-REP\n");
#endif

	      koffsetp = koffset + 4;
	      pad_data_len = packet->payload[koffsetp];
	      /* Skip realm already filled in request */
	      cname_offset = pad_data_len + koffsetp + 15;

	      if(cname_offset < packet->payload_packet_len) {
		u_int8_t cname_len = packet->payload[cname_offset];

		if((cname_offset+cname_offset) < packet->payload_packet_len) {
		  char cname_str[48];
		  
		  if(cname_len > sizeof(cname_str)-1)
		    cname_len = sizeof(cname_str)-1;

		  strncpy(cname_str, (char*)&packet->payload[cname_offset+1], cname_len);
		  cname_str[cname_len] = '\0';
		  for(i=0; i<cname_len; i++) cname_str[i] = tolower(cname_str[i]);

#ifdef KERBEROS_DEBUG
		  printf("[TGS-REP][s/dport: %u/%u][Kerberos Cname][len: %u][%s]\n",
			 sport, dport, cname_len, cname_str);
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
#ifdef KERBEROS_DEBUG
      printf("[Kerberos][s/dport: %u/%u] Skipping packet: too long [kerberos_len: %u]\n",
	     sport, dport, kerberos_len);
#endif

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
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
