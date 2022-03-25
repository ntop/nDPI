/*
 * kerberos.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_KERBEROS

#include "ndpi_api.h"

/* #define KERBEROS_DEBUG 1 */

#define KERBEROS_PORT 88

static int ndpi_search_kerberos_extra(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow);


/* Reference: https://en.wikipedia.org/wiki/X.690#Length_octets */
static int krb_decode_asn1_length(struct ndpi_detection_module_struct *ndpi_struct,
                                  size_t * const kasn1_offset)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  unsigned char length_octet;
  int length;

  length_octet = packet->payload[*kasn1_offset];

  if (length_octet == 0xFF)
  {
    /* Malformed Packet */
    return -1;
  }

  if ((length_octet & 0x80) == 0)
  {
    /* Definite, short */
    length = length_octet & 0x7F;
    (*kasn1_offset)++;
  } else {
    /* Definite, long or indefinite (not support by this implementation) */
    if ((length_octet & 0x7F) == 0)
    {
      /* indefinite, unsupported */
      return -1;
    }

    length_octet &= 0x7F;
    if (length_octet > 4 /* We support only 4 additional length octets. */ ||
        packet->payload_packet_len <= *kasn1_offset + length_octet + 1)
    {
      return -1;
    }

    int i = 1;
    length = 0;
    for (; i <= length_octet; ++i)
    {
      length |= packet->payload[*kasn1_offset + i] << (length_octet - i) * 8;
    }
    *kasn1_offset += i;
  }

  if (packet->payload_packet_len < *kasn1_offset + length)
  {
    return -1;
  }

  return length;
}

/* Reference: https://en.wikipedia.org/wiki/X.690#Identifier_octets */
static int krb_decode_asn1_sequence_type(struct ndpi_detection_module_struct *ndpi_struct,
                                         size_t * const kasn1_offset)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  if (packet->payload_packet_len <= *kasn1_offset + 1 /* length octet */ ||
      packet->payload[*kasn1_offset] != 0x30 /* Universal Constructed Tag Type: Sequence */)
  {
    return -1;
  }

  (*kasn1_offset)++;

  return krb_decode_asn1_length(ndpi_struct, kasn1_offset);
}

/* Reference: https://en.wikipedia.org/wiki/X.690#Identifier_octets */
static int krb_decode_asn1_string_type(struct ndpi_detection_module_struct *ndpi_struct,
                                       size_t * const kasn1_offset,
                                       char const ** const out)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  int length;

  if (packet->payload_packet_len <= *kasn1_offset + 1 /* length octet */ ||
      (packet->payload[*kasn1_offset] != 0xA3 /* Context-specific Constructed Tag Type: Bit String */ &&
       packet->payload[*kasn1_offset] != 0xA4 /* Context-specific Constructed Tag Type: Octect String */ &&
       packet->payload[*kasn1_offset] != 0x30 /* Sequence Of */))
  {
    return -1;
  }

  (*kasn1_offset)++;

  length = krb_decode_asn1_length(ndpi_struct, kasn1_offset);
  if (length <= 0)
  {
    return -1;
  }

  if (out != NULL)
  {
    *out = (char *)&packet->payload[*kasn1_offset];
  }

  return length;
}

/* Reference: https://en.wikipedia.org/wiki/X.690#Identifier_octets */
static int krb_decode_asn1_int_type(struct ndpi_detection_module_struct *ndpi_struct,
                                    size_t * const kasn1_offset,
                                    int * const out)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  int length;

  if (packet->payload_packet_len <= *kasn1_offset + 1 /* length octet */ ||
      packet->payload[*kasn1_offset] != 0x02)
  {
    return -1;
  }

  (*kasn1_offset)++;

  length = krb_decode_asn1_length(ndpi_struct, kasn1_offset);
  if (length <= 0 || length > 4)
  {
    return -1;
  }

  if (out != NULL)
  {
    int i = 0;
    *out = 0;
    for (; i < length; ++i)
    {
      *out |= packet->payload[*kasn1_offset + i] << (length - i - 1) * 8;
    }
    *kasn1_offset += i;
  }

  return length;
}

/* Tags in which we are not interested. */
static int krb_decode_asn1_blocks_skip(struct ndpi_detection_module_struct *ndpi_struct,
                                       size_t * const kasn1_offset)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  int length;

  if (packet->payload_packet_len <= *kasn1_offset + 1 /* length octet */ ||
      (packet->payload[*kasn1_offset] != 0xA0 /* Constructed Context-specific NULL */ &&
       packet->payload[*kasn1_offset] != 0xA1 /* Constructed Context-specific BOOLEAN */ &&
       packet->payload[*kasn1_offset] != 0xA2 /* Constructed Context-specific INTEGER */))
  {
    return -1;
  }

  (*kasn1_offset)++;

  length = krb_decode_asn1_length(ndpi_struct, kasn1_offset);
  if (length < 0)
  {
    return -1;
  }

  return length;
}

static void strncpy_lower(char * const dst, size_t dst_siz,
                          char const * const src, size_t src_siz)
{
   int dst_len = ndpi_min(src_siz, dst_siz - 1);

   strncpy(dst, src, dst_len);
   dst[dst_len] = '\0';

   for(int i = 0; i < dst_len; ++i)
   {
     dst[i] = tolower(dst[i]);
   }
}

/* Reference: https://datatracker.ietf.org/doc/html/rfc4120 */
static int krb_parse(struct ndpi_detection_module_struct * const ndpi_struct,
                     struct ndpi_flow_struct * const flow,
                     size_t payload_offset)
{
  size_t kasn1_offset = payload_offset;
  int length, krb_version, msg_type;
  char const * text;

  length = krb_decode_asn1_sequence_type(ndpi_struct, &kasn1_offset);
  if (length < 0)
  {
    return -1;
  }

  length = krb_decode_asn1_blocks_skip(ndpi_struct, &kasn1_offset);
  if (length < 0)
  {
    return -1;
  }

  length = krb_decode_asn1_int_type(ndpi_struct, &kasn1_offset, &krb_version); /* pvno */
  if (length != 1 || krb_version != 5)
  {
    return -1;
  }

  length = krb_decode_asn1_blocks_skip(ndpi_struct, &kasn1_offset);
  if (length < 0)
  {
    return -1;
  }

  length = krb_decode_asn1_int_type(ndpi_struct, &kasn1_offset, &msg_type); /* msg-type */
  if (length != 1 || msg_type != 0x0d /* TGS-REP */)
  {
    return -1;
  }

  krb_decode_asn1_blocks_skip(ndpi_struct, &kasn1_offset);

  length = krb_decode_asn1_sequence_type(ndpi_struct, &kasn1_offset); /* Optional PADATA */
  if (length > 0)
  {
    kasn1_offset += length;
  }

  length = krb_decode_asn1_string_type(ndpi_struct, &kasn1_offset, &text);
  if (length < 0)
  {
    return -1;
  }

  kasn1_offset += length;
  text += 2;
  length -= 2;
  if (flow->protos.kerberos.domain[0] == '\0')
  {
    strncpy_lower(flow->protos.kerberos.domain, sizeof(flow->protos.kerberos.domain),
                  text, length);
  }

  length = krb_decode_asn1_string_type(ndpi_struct, &kasn1_offset, NULL);
  if (length < 0)
  {
    return -1;
  }

  length = krb_decode_asn1_sequence_type(ndpi_struct, &kasn1_offset);
  if (length < 0)
  {
    return -1;
  }

  length = krb_decode_asn1_blocks_skip(ndpi_struct, &kasn1_offset);
  if (length < 0)
  {
    return -1;
  }
  kasn1_offset += length;

  length = krb_decode_asn1_blocks_skip(ndpi_struct, &kasn1_offset);
  if (length < 0)
  {
    return -1;
  }

  length = krb_decode_asn1_string_type(ndpi_struct, &kasn1_offset, &text);
  if (length < 0)
  {
    return -1;
  }

  kasn1_offset += length;
  text += 2;
  length -= 2;
  if (flow->protos.kerberos.hostname[0] == '\0' && text[length - 1] != '$')
  {
    strncpy_lower(flow->protos.kerberos.hostname, sizeof(flow->protos.kerberos.hostname),
                  text, length);
  } else if (flow->protos.kerberos.username[0] == '\0') {
    strncpy_lower(flow->protos.kerberos.username, sizeof(flow->protos.kerberos.username),
                  text, length - 1);
  }

  return 0;
}

static void ndpi_int_kerberos_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					     struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_KERBEROS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  NDPI_LOG_DBG(ndpi_struct, "trace KERBEROS\n");
}

/* ************************************************* */

void ndpi_search_kerberos(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t sport = packet->tcp ? ntohs(packet->tcp->source) : ntohs(packet->udp->source);
  u_int16_t dport = packet->tcp ? ntohs(packet->tcp->dest) : ntohs(packet->udp->dest);
  const u_int8_t *original_packet_payload = NULL;
  u_int16_t original_payload_packet_len = 0;

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
	original_packet_payload = packet->payload;
	original_payload_packet_len = packet->payload_packet_len;
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
	    u_int16_t koffsetp, body_offset = 0, pad_len;
	    u_int8_t msg_type = packet->payload[koffset];

#ifdef KERBEROS_DEBUG
	    printf("[Kerberos] Packet found 0x%02X/%u\n", msg_type, msg_type);
#endif

	    ndpi_int_kerberos_add_connection(ndpi_struct, flow);

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

	      for(i=0; i<10; i++) if(body_offset<packet->payload_packet_len && packet->payload[body_offset] != 0x05) body_offset++; /* ASN.1 */
#ifdef KERBEROS_DEBUG
	      printf("body_offset=%u [%02X %02X] [byte 0 must be 0x05]\n", body_offset, packet->payload[body_offset], packet->payload[body_offset+1]);
#endif
	    }
	    
	    if(msg_type == 0x0A) /* AS-REQ */ {
#ifdef KERBEROS_DEBUG
	      printf("[Kerberos] Processing AS-REQ\n");
#endif


	      if(body_offset < packet->payload_packet_len) {
		u_int16_t name_offset = body_offset + 13;
		
		for(i=0; (i<20) && (name_offset < packet->payload_packet_len); i++) {
		  if(packet->payload[name_offset] != 0x1b)
		    name_offset++; /* ASN.1 */
		}
		
#ifdef KERBEROS_DEBUG
		printf("name_offset=%u [%02X %02X] [byte 0 must be 0x1b]\n", name_offset, packet->payload[name_offset], packet->payload[name_offset+1]);
#endif

		if(name_offset < packet->payload_packet_len - 1) {
		  u_int cname_len = 0;

		  name_offset += 1;
		  if(name_offset < packet->payload_packet_len - 1 &&
		     isprint(packet->payload[name_offset+1]) == 0) /* Isn't printable ? */
		  {
		    name_offset++;
		  }

		  if(name_offset < packet->payload_packet_len - 3 &&
		     packet->payload[name_offset+1] == 0x1b)
		  {
		    name_offset += 2;
		  }
		  
		  cname_len = packet->payload[name_offset];

		  if((cname_len+name_offset) < packet->payload_packet_len) {
		    u_int realm_len, realm_offset;
		    char cname_str[48];
		    u_int8_t num_cname = 0;

			cname_str[0] = '\0'; // required, because cname_len

		    while(++num_cname <= 2) {
		      if(cname_len > sizeof(cname_str)-1)
		        cname_len = sizeof(cname_str)-1;

		      if (name_offset + cname_len + 1 >= packet->payload_packet_len)
		        cname_len = 0;
		      else
		        strncpy(cname_str, (char*)&packet->payload[name_offset+1], cname_len);
		      cname_str[cname_len] = '\0';
		      for(i=0; i<cname_len; i++) cname_str[i] = tolower(cname_str[i]);

#ifdef KERBEROS_DEBUG
		      printf("[AS-REQ][s/dport: %u/%u][Kerberos Cname][len: %u][%s]\n", sport, dport, cname_len, cname_str);
#endif

		      if(((strcmp(cname_str, "host") == 0) || (strcmp(cname_str, "ldap") == 0)) && (packet->payload[name_offset+1+cname_len] == 0x1b) && num_cname == 1) {
		        name_offset += cname_len + 2;
		        if (name_offset < packet->payload_packet_len)
		          cname_len = packet->payload[name_offset];
		      } else{
		        break;
		      }
		    }

		    realm_offset = cname_len + name_offset + 3;

		    /* if cname does not end with a $ then it's a username */
		    if(cname_len > 0 && name_offset + cname_len + 1 < packet->payload_packet_len
		       && (cname_len < sizeof(cname_str))
		       && (cname_str[cname_len-1] == '$')) {
		      cname_str[cname_len-1] = '\0';
		      snprintf(flow->protos.kerberos.hostname, sizeof(flow->protos.kerberos.hostname), "%s", cname_str);
		    } else
		      snprintf(flow->protos.kerberos.username, sizeof(flow->protos.kerberos.username), "%s", cname_str);

		    for(i=0; (i < 14) && (realm_offset <  packet->payload_packet_len); i++) {
		      if(packet->payload[realm_offset] != 0x1b)
			realm_offset++; /* ASN.1 */
		    }
		    
#ifdef KERBEROS_DEBUG
		    printf("realm_offset=%u [%02X %02X] [byte 0 must be 0x1b]\n", realm_offset,
			   packet->payload[realm_offset], packet->payload[realm_offset+1]);
#endif
		    
		    realm_offset += 1;
		    //if(num_cname == 2) realm_offset++;
		    if(realm_offset  < packet->payload_packet_len) {
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
	      } 
#ifdef KERBEROS_DEBUG
	      printf("[Kerberos] Setting extra func from AS-REQ\n");
#endif
	      flow->check_extra_packets = 1;
	      flow->max_extra_packets_to_check = 5; /* Reply may be split into multiple segments */
	      flow->extra_packets_func = ndpi_search_kerberos_extra;
	    } else if(msg_type == 0x0e) /* AS-REQ */ {
#ifdef KERBEROS_DEBUG
	      printf("[Kerberos] Processing AS-REQ\n");
#endif
	      /* Nothing specific to do; stop dissecting this flow */
	      flow->extra_packets_func = NULL;

	    } else if(msg_type == 0x0c) /* TGS-REQ */ {
#ifdef KERBEROS_DEBUG
	      printf("[Kerberos] Processing TGS-REQ\n");
#endif

	      if(body_offset < packet->payload_packet_len) {
		u_int16_t name_offset, padding_offset = body_offset + 4;

		name_offset = padding_offset;
		for(i=0; i<14 && name_offset < packet->payload_packet_len; i++) if(packet->payload[name_offset] != 0x1b) name_offset++; /* ASN.1 */

#ifdef KERBEROS_DEBUG
		printf("name_offset=%u [%02X %02X] [byte 0 must be 0x1b]\n", name_offset, packet->payload[name_offset], packet->payload[name_offset+1]);
#endif

		if(name_offset < (packet->payload_packet_len - 1)) {
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
		    if(flow->kerberos_buf.pktbuf) {
			    ndpi_free(flow->kerberos_buf.pktbuf);
			    packet->payload = original_packet_payload;
			    packet->payload_packet_len = original_payload_packet_len;
		    }
		    flow->kerberos_buf.pktbuf = NULL;
		  }
		}
	      }
#ifdef KERBEROS_DEBUG
	      printf("[Kerberos] Setting extra func from TGS-REQ\n");
#endif
	      if(!packet->udp) {
	        flow->check_extra_packets = 1;
	        flow->max_extra_packets_to_check = 5; /* Reply may be split into multiple segments */
	        flow->extra_packets_func = ndpi_search_kerberos_extra;
	      }

	      if(flow->kerberos_buf.pktbuf != NULL) {
		ndpi_free(flow->kerberos_buf.pktbuf);
		packet->payload = original_packet_payload;
		packet->payload_packet_len = original_payload_packet_len;
		flow->kerberos_buf.pktbuf = NULL;
	      }

	      return;
	    } else if(msg_type == 0x0d) /* TGS-REP */ {
	      NDPI_LOG_DBG(ndpi_struct, "[Kerberos] Processing TGS-REP\n");

	      if (krb_parse(ndpi_struct, flow, 8) != 0)
	      {
	        NDPI_LOG_ERR(ndpi_struct, "[TGS-REP] Invalid packet received\n");
	        return;
	      }
	      NDPI_LOG_DBG(ndpi_struct,
	                   "[TGS-REP][s/dport: %u/%u][Kerberos Hostname,Domain,Username][%s,%s,%s]\n",
	                   sport, dport, flow->protos.kerberos.hostname, flow->protos.kerberos.domain,
	                   flow->protos.kerberos.username);
	      flow->extra_packets_func = NULL;
	    }

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

static int ndpi_search_kerberos_extra(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

#ifdef KERBEROS_DEBUG
  printf("[Kerberos] Extra function\n");
#endif

  /* Unfortunately, generic "extra function" code doesn't honour protocol bitmask */
  /* TODO: handle that in ndpi_main.c for all the protocols */
  if(packet->payload_packet_len == 0 ||
     packet->tcp_retransmission)
    return 1;

  /* Possibly dissect the reply */
  ndpi_search_kerberos(ndpi_struct, flow);

  /* Possibly more processing */
  return 1;
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
