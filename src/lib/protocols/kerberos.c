/*
 * kerberos.c
 *
 * Copyright (C) 2011-26 - ntop.org
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
#include "ndpi_private.h"

/* #define KERBEROS_DEBUG 1 */

#define KERBEROS_PORT 88

#define KRB_MAX_MSG_LEN 12000

/* Reference: https://datatracker.ietf.org/doc/html/rfc4120#section-5.10 */
#define KRB_MSG_TYPE_AS_REQ  10
#define KRB_MSG_TYPE_AS_REP  11
#define KRB_MSG_TYPE_TGS_REQ 12
#define KRB_MSG_TYPE_TGS_REP 13
#define KRB_MSG_TYPE_AP_REQ  14
#define KRB_MSG_TYPE_ERROR   30

static int ndpi_search_kerberos_extra(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow);


/* KerberosString (i.e. GeneralString) */
static int krb_decode_asn1_string(const u_int8_t *buf, u_int32_t buf_len,
                                  struct asn1_ber_tlv * const tlv)
{
  if (asn1_ber_decode_single_tlv(buf, buf_len, tlv) != 0 ||
      (tlv->tag != 0x1B /* GeneralString */ &&
       tlv->tag != 0x0C /* UTF8String */ &&
       tlv->tag != 0x16 /* IA5String */))
  {
    return -1;
  }

  return 0;
}

static void krb_strncpy_lower(char * const dst, size_t dst_siz,
                              char const * const src, size_t src_siz)
{
  int i, dst_len = (int)ndpi_min(src_siz, dst_siz - 1);

   dst[dst_len] = '\0';

   for(i = 0; i < dst_len; ++i)
   {
     if (ndpi_isprint(src[i]) == 0)
     {
       dst[i] = '?';
     } else {
       dst[i] = tolower((unsigned char)src[i]);
     }
   }
}

/* Realm ::= KerberosString */
static void krb_parse_realm(struct ndpi_flow_struct * const flow,
                            const u_int8_t *buf, u_int32_t buf_len)
{
  struct asn1_ber_tlv realm;

  if (krb_decode_asn1_string(buf, buf_len, &realm) != 0 || realm.length == 0)
  {
    return;
  }

  if (flow->metadata.protos.kerberos.domain[0] == '\0')
  {
    krb_strncpy_lower(flow->metadata.protos.kerberos.domain, sizeof(flow->metadata.protos.kerberos.domain),
                      (char const *)realm.value, realm.length);
  }
}

/*
  PrincipalName ::= SEQUENCE {
    name-type   [0] Int32,
    name-string [1] SEQUENCE OF KerberosString
  }
*/
static void krb_parse_cname(struct ndpi_flow_struct * const flow,
                            const u_int8_t *buf, u_int32_t buf_len)
{
  struct asn1_ber_tlv seq, field, names, name[2];
  u_int8_t num_names = 0, idx = 0;
  int used;

  if (asn1_ber_decode_single_tlv(buf, buf_len, &seq) != 0 || seq.tag != 0x30)
  {
    return;
  }

  /* Looking for name-string */
  field.tag = 0;
  while (seq.length > 0)
  {
    used = asn1_ber_decode_tlv(seq.value, seq.length, &field);
    if (used < 0)
    {
      return;
    }
    if (field.tag == 0xA1)
    {
      break;
    }
    seq.value += used;
    seq.length -= used;
  }

  if (field.tag != 0xA1 ||
      asn1_ber_decode_single_tlv(field.value, field.length, &names) != 0 || names.tag != 0x30)
  {
    return;
  }

  while (names.length > 0 && num_names < 2)
  {
    struct asn1_ber_tlv tlv;

    used = asn1_ber_decode_tlv(names.value, names.length, &tlv);
    if (used < 0 || krb_decode_asn1_string(names.value, used, &name[num_names]) != 0)
    {
      return;
    }
    num_names++;
    names.value += used;
    names.length -= used;
  }

  /* Service-like principals: the second component is the interesting one */
  if (num_names == 2 && name[0].length == 4 &&
      (strncasecmp((char const *)name[0].value, "host", 4) == 0 ||
       strncasecmp((char const *)name[0].value, "ldap", 4) == 0))
  {
    idx = 1;
  }

  if (num_names <= idx || name[idx].length == 0 ||
      flow->metadata.protos.kerberos.hostname[0] != '\0' ||
      flow->metadata.protos.kerberos.username[0] != '\0')
  {
    return;
  }

  /* If cname ends with a $ then it's a machine account, otherwise it's a username */
  if (name[idx].value[name[idx].length - 1] == '$')
  {
    krb_strncpy_lower(flow->metadata.protos.kerberos.hostname, sizeof(flow->metadata.protos.kerberos.hostname),
                      (char const *)name[idx].value, name[idx].length - 1);
  } else {
    krb_strncpy_lower(flow->metadata.protos.kerberos.username, sizeof(flow->metadata.protos.kerberos.username),
                      (char const *)name[idx].value, name[idx].length);
  }
}

/*
  KDC-REQ-BODY ::= SEQUENCE {
    kdc-options [0] KDCOptions,
    cname       [1] PrincipalName OPTIONAL,
    realm       [2] Realm,
    ...
  }
*/
static void krb_parse_req_body(struct ndpi_flow_struct * const flow,
                               const u_int8_t *buf, u_int32_t buf_len)
{
  struct asn1_ber_tlv seq, field;
  int used;

  if (asn1_ber_decode_single_tlv(buf, buf_len, &seq) != 0 || seq.tag != 0x30)
  {
    return;
  }

  while (seq.length > 0)
  {
    used = asn1_ber_decode_tlv(seq.value, seq.length, &field);
    if (used < 0 || field.tag > 0xA2)
    {
      return;
    }

    if (field.tag == 0xA1)
    {
      krb_parse_cname(flow, field.value, field.length);
    } else if (field.tag == 0xA2) {
      krb_parse_realm(flow, field.value, field.length);
    }

    seq.value += used;
    seq.length -= used;
  }
}

static int krb_is_valid_msg_type(u_int8_t msg_type)
{
  return msg_type == KRB_MSG_TYPE_AS_REQ || msg_type == KRB_MSG_TYPE_AS_REP ||
         msg_type == KRB_MSG_TYPE_TGS_REQ || msg_type == KRB_MSG_TYPE_TGS_REP ||
         msg_type == KRB_MSG_TYPE_AP_REQ || msg_type == KRB_MSG_TYPE_ERROR;
}

static int krb_is_request(u_int8_t msg_type)
{
  return msg_type == KRB_MSG_TYPE_AS_REQ || msg_type == KRB_MSG_TYPE_TGS_REQ;
}

/* Check if the buffer is the beginning of a (possibly truncated) message long msg_len bytes */
static int krb_is_msg_start(const u_int8_t *buf, u_int32_t buf_len, u_int32_t msg_len)
{
  u_int8_t tag;
  u_int32_t length;
  int hdr_len = asn1_ber_decode_header(buf, buf_len, &tag, &length);

  return hdr_len > 0 &&
         (tag & 0xE0) == 0x60 /* Application Constructed */ &&
         krb_is_valid_msg_type(tag & 0x1F) &&
         (u_int32_t)hdr_len + length == msg_len;
}

/*
  Reference: https://datatracker.ietf.org/doc/html/rfc4120#section-5

  KDC-REQ   ::= SEQUENCE { pvno [1], msg-type [2], padata [3] OPTIONAL, req-body [4] }
  KDC-REP   ::= SEQUENCE { pvno [0], msg-type [1], padata [2] OPTIONAL, crealm [3], cname [4],
                           ticket [5], enc-part [6] }
  KRB-ERROR ::= SEQUENCE { pvno [0], msg-type [1], ctime [2] OPTIONAL, cusec [3] OPTIONAL,
                           stime [4], susec [5], error-code [6], crealm [7] OPTIONAL,
                           cname [8] OPTIONAL, realm [9], sname [10], ... }

  Returns the message type or -1
*/
static int krb_parse(struct ndpi_detection_module_struct * const ndpi_struct,
                     struct ndpi_flow_struct * const flow,
                     const u_int8_t *buf, u_int32_t buf_len)
{
  struct asn1_ber_tlv app, seq, field;
  u_int8_t msg_type, pvno_idx, idx, pvno_found = 0, msg_type_found = 0;
  int32_t value;
  int used;

  if (asn1_ber_decode_single_tlv(buf, buf_len, &app) != 0 ||
      (app.tag & 0xE0) != 0x60 /* Application Constructed */ ||
      asn1_ber_decode_single_tlv(app.value, app.length, &seq) != 0 ||
      seq.tag != 0x30)
  {
    return -1;
  }

  msg_type = app.tag & 0x1F;
  if (!krb_is_valid_msg_type(msg_type))
  {
    return -1;
  }
  pvno_idx = krb_is_request(msg_type) ? 1 : 0;

  while (seq.length > 0)
  {
    used = asn1_ber_decode_tlv(seq.value, seq.length, &field);
    if (used < 0 || (field.tag & 0xE0) != 0xA0 /* Context-specific Constructed */)
    {
      break;
    }
    seq.value += used;
    seq.length -= used;
    idx = field.tag & 0x1F;

    if (idx == pvno_idx)
    {
      if (asn1_ber_decode_int(field.value, field.length, &value) != 0 || value != 5)
      {
        return -1;
      }
      pvno_found = 1;
      continue;
    }
    if (idx == pvno_idx + 1)
    {
      if (asn1_ber_decode_int(field.value, field.length, &value) != 0 || value != msg_type)
      {
        return -1;
      }
      msg_type_found = 1;
      continue;
    }
    if (!pvno_found || !msg_type_found)
    {
      return -1;
    }

    switch (msg_type)
    {
      case KRB_MSG_TYPE_AS_REQ:
      case KRB_MSG_TYPE_TGS_REQ:
        if (idx == 4)
        {
          krb_parse_req_body(flow, field.value, field.length);
        }
        break;

      case KRB_MSG_TYPE_AS_REP:
      case KRB_MSG_TYPE_TGS_REP:
        if (idx == 3)
        {
          krb_parse_realm(flow, field.value, field.length);
        } else if (idx == 4) {
          krb_parse_cname(flow, field.value, field.length);
        }
        break;

      case KRB_MSG_TYPE_ERROR:
        if (idx == 6)
        {
          if (asn1_ber_decode_int(field.value, field.length, &value) == 0 &&
              flow->metadata.protos.kerberos.rep_msg_type == 0)
          {
            flow->metadata.protos.kerberos.error_code = value;
          }
        } else if (idx == 7 || idx == 9) {
          krb_parse_realm(flow, field.value, field.length);
        } else if (idx == 8) {
          krb_parse_cname(flow, field.value, field.length);
        }
        break;

      default:
        break;
    }
  }

  if (!pvno_found || !msg_type_found)
  {
    return -1;
  }

  /* Only the first request and the first reply are exported */
  if (krb_is_request(msg_type))
  {
    if (flow->metadata.protos.kerberos.req_msg_type == 0)
    {
      flow->metadata.protos.kerberos.req_msg_type = msg_type;
    }
  } else if (msg_type != KRB_MSG_TYPE_AP_REQ) {
    if (flow->metadata.protos.kerberos.rep_msg_type == 0)
    {
      flow->metadata.protos.kerberos.rep_msg_type = msg_type;
    }
  }

  NDPI_LOG_DBG(ndpi_struct,
               "[msg-type: %u][Kerberos Hostname,Domain,Username][%s,%s,%s]\n",
               msg_type, flow->metadata.protos.kerberos.hostname, flow->metadata.protos.kerberos.domain,
               flow->metadata.protos.kerberos.username);

  return msg_type;
}

static void ndpi_int_kerberos_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					     struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, &flow->core, NDPI_PROTOCOL_KERBEROS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  NDPI_LOG_INFO(ndpi_struct, "found KERBEROS\n");
}

static void krb_free_buf(struct ndpi_flow_struct *flow) {
  if(flow->metadata.kerberos_buf.pktbuf != NULL) {
    ndpi_free(flow->metadata.kerberos_buf.pktbuf);
    flow->metadata.kerberos_buf.pktbuf = NULL;
  }
}

/* ************************************************* */

/* Returns the type of the message found, 0 if we need more data or -1 if it is not Kerberos */
static int krb_process_packet(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len, kerberos_len;
  int msg_type;

#ifdef KERBEROS_DEBUG
  printf("\n[Kerberos] Process packet [len: %u]\n", packet->payload_packet_len);
#endif

  if(flow->metadata.kerberos_buf.pktbuf != NULL) {
    u_int missing = flow->metadata.kerberos_buf.pktbuf_maxlen - flow->metadata.kerberos_buf.pktbuf_currlen;

    if(payload_len <= missing) {
      memcpy(&flow->metadata.kerberos_buf.pktbuf[flow->metadata.kerberos_buf.pktbuf_currlen], payload, payload_len);
      flow->metadata.kerberos_buf.pktbuf_currlen += payload_len;

      if(flow->metadata.kerberos_buf.pktbuf_currlen < flow->metadata.kerberos_buf.pktbuf_maxlen) {
#ifdef KERBEROS_DEBUG
	printf("[Kerberos] Missing %u bytes: skipping\n",
	       flow->metadata.kerberos_buf.pktbuf_maxlen - flow->metadata.kerberos_buf.pktbuf_currlen);
#endif
	return 0;
      }

#ifdef KERBEROS_DEBUG
      printf("[Kerberos] Packet is now full: processing\n");
#endif
      payload = (const u_int8_t *)flow->metadata.kerberos_buf.pktbuf;
      payload_len = flow->metadata.kerberos_buf.pktbuf_currlen;
    } else {
      /* Unexpected segment: forget the partial message and start again from this packet */
      krb_free_buf(flow);
    }
  }

  if(packet->tcp) {
    /* Record Marking: https://datatracker.ietf.org/doc/html/rfc4120#section-7.2.2 */
    if(payload_len < 4)
      return -1;

    kerberos_len = ntohl(get_u_int32_t(payload, 0));
    payload += 4, payload_len -= 4;

#ifdef KERBEROS_DEBUG
    printf("[Kerberos] [Kerberos len: %u][available: %u]\n", kerberos_len, payload_len);
#endif

    if(kerberos_len >= KRB_MAX_MSG_LEN || kerberos_len < payload_len)
      return -1;

    if(kerberos_len > payload_len) {
      /*
	Kerberos packets might be too long for a TCP packet
	so it could be split across multiple packets. Instead of
	rebuilding the stream we use a heuristic approach
      */
      if(!krb_is_msg_start(payload, payload_len, kerberos_len))
	return -1;

      flow->metadata.kerberos_buf.pktbuf = (char*)ndpi_malloc(kerberos_len+4);
      if(flow->metadata.kerberos_buf.pktbuf == NULL)
	return -1;

      flow->metadata.kerberos_buf.pktbuf_maxlen = kerberos_len+4;
      memcpy(flow->metadata.kerberos_buf.pktbuf, payload-4, payload_len+4);
      flow->metadata.kerberos_buf.pktbuf_currlen = payload_len+4;
#ifdef KERBEROS_DEBUG
      printf("[Kerberos] Allocated %u bytes\n", flow->metadata.kerberos_buf.pktbuf_maxlen);
#endif
      return 0;
    }
  }

  msg_type = krb_parse(ndpi_struct, flow, payload, payload_len);

#ifdef KERBEROS_DEBUG
  printf("[Kerberos] [msg-type: %d]\n", msg_type);
#endif

  krb_free_buf(flow);

  return msg_type;
}

static void krb_message_found(struct ndpi_flow_struct *flow, int msg_type) {
  if(krb_is_request(msg_type)) {
    /* Looking for the reply */
    flow->core.max_extra_packets_to_check = 5; /* Reply may be split into multiple segments */
    flow->core.extra_packets_func = ndpi_search_kerberos_extra;
  } else {
    /* Nothing else to do; stop dissecting this flow */
    flow->core.extra_packets_func = NULL;
  }
}

static void ndpi_search_kerberos(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t sport = packet->tcp ? ntohs(packet->tcp->source) : ntohs(packet->udp->source);
  u_int16_t dport = packet->tcp ? ntohs(packet->tcp->dest) : ntohs(packet->udp->dest);
  int msg_type;

  if((sport != KERBEROS_PORT) && (dport != KERBEROS_PORT)) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  NDPI_LOG_DBG(ndpi_struct, "search KERBEROS\n");

  msg_type = krb_process_packet(ndpi_struct, flow);
  if(msg_type < 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }
  if(msg_type == 0)
    return;

  ndpi_int_kerberos_add_connection(ndpi_struct, flow);
  krb_message_found(flow, msg_type);
}

static int ndpi_search_kerberos_extra(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int msg_type;

#ifdef KERBEROS_DEBUG
  printf("[Kerberos] Extra function\n");
#endif

  /* Unfortunately, generic "extra function" code doesn't honour protocol bitmask */
  /* TODO: handle that in ndpi_main.c for all the protocols */
  if(packet->payload_packet_len == 0 ||
     packet->tcp_retransmission)
    return 1;

  /* Possibly dissect the reply */
  msg_type = krb_process_packet(ndpi_struct, flow);
  if(msg_type > 0)
    krb_message_found(flow, msg_type);

  /* Possibly more processing */
  return flow->core.extra_packets_func != NULL;
}

void init_kerberos_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("Kerberos", ndpi_struct,
                     ndpi_search_kerberos,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                      DISSECTOR_LICENSE_LGPL,
                      1, NDPI_PROTOCOL_KERBEROS);
}
