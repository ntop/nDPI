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

/*
  Max bytes of a message buffered per flow, when it is split in several TCP
  segments:
  - requests: the whole message is needed; longer ones are not reassembled
  - replies: only the beginning of the message, up to the client name, is
    needed (replies of any size are accepted). It is before the ticket (that
    can be very large, e.g. with the PAC of a user in many groups) and usually
    in the first TCP segment, but it can be in the next ones (e.g. a large
    padata, as with PKINIT, small segments or the record marker in its own
    segment)
*/
#define KRB_MAX_BUF_LEN       12000
#define KRB_MAX_REPLY_LEN     (1 << 20) /* Sanity check of the record marker */
/* The packets to wait for the reply are configurable
   (kerberos,max_packets_extra_dissection): the default (16) is enough for
   KRB_MAX_BUF_LEN bytes with delayed ACKs (MSS 1460: 9 segments + 5 ACKs) */

/* krb_parse() modes */
#define KRB_PARSE_FULL         0 /* The whole message */
#define KRB_PARSE_PREFIX       1 /* The beginning of the message: may need more data */
#define KRB_PARSE_PREFIX_FINAL 2 /* The beginning of the message: no more data */

/* Reference: https://datatracker.ietf.org/doc/html/rfc4120#section-5.10 */
#define KRB_MSG_TYPE_AS_REQ  10
#define KRB_MSG_TYPE_AS_REP  11
#define KRB_MSG_TYPE_TGS_REQ 12
#define KRB_MSG_TYPE_TGS_REP 13
#define KRB_MSG_TYPE_AP_REQ  14
#define KRB_MSG_TYPE_ERROR   30

/* Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu */
#define KRB_PADATA_FOR_USER           129 /* S4U2Self */
#define KRB_PADATA_S4U_X509_USER      130 /* S4U2Self with a certificate */
#define KRB_KDC_OPT_CNAME_IN_ADDL_TKT 14  /* S4U2Proxy */

static int ndpi_search_kerberos_extra(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow);


/* KerberosString (i.e. GeneralString) */
static int krb_decode_asn1_string(const u_int8_t *buf, u_int32_t buf_len,
                                  struct ndpi_asn1_ber_tlv * const tlv)
{
  if (ndpi_asn1_ber_decode_single_tlv(buf, buf_len, tlv) != 0 ||
      (tlv->tag != 0x1B /* GeneralString */ &&
       tlv->tag != 0x0C /* UTF8String */ &&
       tlv->tag != 0x16 /* IA5String */))
  {
    return -1;
  }

  return 0;
}

/* Length of the valid UTF-8 multi-byte sequence starting at buf, or 0 */
static size_t krb_utf8_seq_len(const u_int8_t *buf, size_t len)
{
  size_t n, i;
  u_int8_t min = 0x80, max = 0xBF; /* Range of the second byte */

  if (buf[0] >= 0xC2 && buf[0] <= 0xDF) {
    n = 2;
  } else if (buf[0] >= 0xE0 && buf[0] <= 0xEF) {
    n = 3;
    if (buf[0] == 0xE0) min = 0xA0; /* Overlong */
    if (buf[0] == 0xED) max = 0x9F; /* Surrogates */
  } else if (buf[0] >= 0xF0 && buf[0] <= 0xF4) {
    n = 4;
    if (buf[0] == 0xF0) min = 0x90; /* Overlong */
    if (buf[0] == 0xF4) max = 0x8F; /* > U+10FFFF */
  } else {
    return 0;
  }

  if (len < n || buf[1] < min || buf[1] > max)
    return 0;

  for (i = 2; i < n; i++)
  {
    if (buf[i] < 0x80 || buf[i] > 0xBF)
      return 0;
  }

  return n;
}

/*
  Copy a name: ASCII is lowercased, valid UTF-8 is kept as is, control
  characters and invalid bytes are replaced by '?'. A multi-byte character
  is never split. Returns 1 if the name has been truncated, 0 otherwise
*/
static u_int8_t krb_copy_name(char * const dst, size_t dst_siz,
                              const u_int8_t *src, size_t src_len)
{
  size_t i = 0, j = 0, n;

  while (i < src_len)
  {
    n = (src[i] < 0x80) ? 0 : krb_utf8_seq_len(&src[i], src_len - i);

    if (j + ndpi_max(n, 1) > dst_siz - 1)
    {
      dst[j] = '\0';
      return 1;
    }

    if (n > 0)
    {
      memcpy(&dst[j], &src[i], n);
      i += n, j += n;
    } else {
      dst[j++] = (src[i] < 0x80 && ndpi_isprint(src[i])) ? tolower(src[i]) : '?';
      i++;
    }
  }

  dst[j] = '\0';
  return 0;
}

/*
  Names and realm are taken from the first message that carries them, except
  for a successful reply (AS-REP/TGS-REP): its crealm and cname, set by the
  KDC, replace the ones of the request, set by the client (e.g. the request
  realm can be the short name of the domain, "CORP" instead of "CORP.LOCAL")
*/

/* Realm ::= KerberosString */
static void krb_parse_realm(struct ndpi_kerberos_metadata * const krb,
                            const u_int8_t *buf, u_int32_t buf_len,
                            u_int8_t overwrite)
{
  struct ndpi_asn1_ber_tlv realm;

  if (krb_decode_asn1_string(buf, buf_len, &realm) != 0 || realm.length == 0)
  {
    return;
  }

  if (overwrite || krb->domain[0] == '\0')
  {
    krb->domain_truncated =
      krb_copy_name(krb->domain, sizeof(krb->domain),
                    realm.value, realm.length);
  }
}

/*
  Length of the short name of a machine (e.g. "ws1" of "ws1.corp.local"), the
  same form as its account name ("WS1$"): the first label of the name, unless
  it is an IPv4 address
*/
static u_int32_t krb_machine_name_len(const u_int8_t *name, u_int32_t name_len)
{
  u_int32_t i, dot = name_len;
  u_int8_t ipv4 = 1;

  for (i = 0; i < name_len; i++)
  {
    if (name[i] == '.')
    {
      if (dot == name_len)
        dot = i;
    } else if (!ndpi_isdigit(name[i])) {
      ipv4 = 0;
    }
  }

  return (ipv4 && dot < name_len) ? name_len : dot;
}

/*
  PrincipalName ::= SEQUENCE {
    name-type   [0] Int32,
    name-string [1] SEQUENCE OF KerberosString
  }
*/
static void krb_parse_cname(struct ndpi_kerberos_metadata * const krb,
                            const u_int8_t *buf, u_int32_t buf_len,
                            u_int8_t overwrite)
{
  struct ndpi_asn1_ber_tlv seq, field, names, name[2];
  u_int8_t num_names = 0, name_type_found = 0;
  int32_t name_type = 0;
  int used;

  if (ndpi_asn1_ber_decode_single_tlv(buf, buf_len, &seq) != 0 || seq.tag != 0x30)
  {
    return;
  }

  /* Looking for name-type and name-string */
  field.tag = 0;
  while (seq.length > 0)
  {
    used = ndpi_asn1_ber_decode_tlv(seq.value, seq.length, &field);
    if (used < 0)
    {
      return;
    }
    if (field.tag == 0xA0)
    {
      name_type_found = (ndpi_asn1_ber_decode_int(field.value, field.length, &name_type) == 0);
    } else if (field.tag == 0xA1) {
      break;
    }
    seq.value += used;
    seq.length -= used;
  }

  if (field.tag != 0xA1 ||
      ndpi_asn1_ber_decode_single_tlv(field.value, field.length, &names) != 0 || names.tag != 0x30)
  {
    return;
  }

  while (names.length > 0 && num_names < 2)
  {
    struct ndpi_asn1_ber_tlv tlv;

    used = ndpi_asn1_ber_decode_tlv(names.value, names.length, &tlv);
    if (used < 0 || krb_decode_asn1_string(names.value, used, &name[num_names]) != 0)
    {
      return;
    }
    num_names++;
    names.value += used;
    names.length -= used;
  }

  if (num_names == 0 || name[0].length == 0 ||
      (!overwrite &&
       (krb->hostname[0] != '\0' ||
        krb->username[0] != '\0' ||
        krb->name_type_found)))
  {
    return;
  }

  /* Only one of them is set: the name of the reply replaces both */
  krb->hostname[0] = '\0';
  krb->username[0] = '\0';
  krb->hostname_truncated = 0;
  krb->username_truncated = 0;
  krb->name_type = name_type;
  krb->name_type_found = name_type_found;

  if (num_names == 2)
  {
    /* Service principals (e.g. "nfs/server.corp.local"): the first component
       is the service, not a user. Only for "host" and "ldap" the second
       component is the name of the machine */
    if (name[0].length == 4 &&
        (strncasecmp((char const *)name[0].value, "host", 4) == 0 ||
         strncasecmp((char const *)name[0].value, "ldap", 4) == 0))
    {
      u_int32_t len = krb_machine_name_len(name[1].value, name[1].length);

      if (len > 0)
      {
        krb->hostname_truncated =
          krb_copy_name(krb->hostname, sizeof(krb->hostname),
                        name[1].value, len);
      }
    }
    return;
  }

  /* If cname ends with a $ then it's a machine account, otherwise it's a username */
  if (name[0].value[name[0].length - 1] == '$')
  {
    krb->hostname_truncated =
      krb_copy_name(krb->hostname, sizeof(krb->hostname),
                    name[0].value, name[0].length - 1);
  } else {
    krb->username_truncated =
      krb_copy_name(krb->username, sizeof(krb->username),
                    name[0].value, name[0].length);
  }
}

/*
  METHOD-DATA ::= SEQUENCE OF PA-DATA

  PA-DATA ::= SEQUENCE {
    padata-type  [1] Int32,
    padata-value [2] OCTET STRING
  }
*/
static void krb_parse_tgs_req_padata(struct ndpi_kerberos_metadata * const krb,
                                     const u_int8_t *buf, u_int32_t buf_len)
{
  struct ndpi_asn1_ber_tlv seq, padata, field;
  int32_t padata_type;
  int used;

  if (ndpi_asn1_ber_decode_single_tlv(buf, buf_len, &seq) != 0 || seq.tag != 0x30)
  {
    return;
  }

  while (seq.length > 0)
  {
    used = ndpi_asn1_ber_decode_tlv(seq.value, seq.length, &padata);
    if (used < 0)
    {
      return;
    }
    seq.value += used;
    seq.length -= used;

    if (padata.tag != 0x30)
    {
      continue;
    }

    while (padata.length > 0)
    {
      used = ndpi_asn1_ber_decode_tlv(padata.value, padata.length, &field);
      if (used < 0)
      {
        return;
      }
      padata.value += used;
      padata.length -= used;

      if (field.tag == 0xA1)
      {
        if (ndpi_asn1_ber_decode_int(field.value, field.length, &padata_type) == 0 &&
            (padata_type == KRB_PADATA_FOR_USER || padata_type == KRB_PADATA_S4U_X509_USER) &&
            krb->s4u == NDPI_KERBEROS_S4U_NONE)
        {
          krb->s4u = NDPI_KERBEROS_S4U2SELF;
        }
        break;
      }
    }
  }
}

/* KDCOptions ::= KerberosFlags (BIT STRING) */
static int krb_kdc_option_is_set(const u_int8_t *buf, u_int32_t buf_len, u_int8_t bit)
{
  struct ndpi_asn1_ber_tlv flags;

  /* The first byte is the number of unused bits */
  return ndpi_asn1_ber_decode_single_tlv(buf, buf_len, &flags) == 0 &&
         flags.tag == 0x03 /* BIT STRING */ &&
         flags.length > 1u + bit / 8 &&
         (flags.value[1 + bit / 8] & (0x80 >> (bit % 8))) != 0;
}

/*
  KDC-REQ-BODY ::= SEQUENCE {
    kdc-options [0] KDCOptions,
    cname       [1] PrincipalName OPTIONAL,
    realm       [2] Realm,
    ...
  }
*/
static void krb_parse_req_body(struct ndpi_kerberos_metadata * const krb,
                               const u_int8_t *buf, u_int32_t buf_len,
                               u_int8_t msg_type)
{
  struct ndpi_asn1_ber_tlv seq, field;
  int used;

  if (ndpi_asn1_ber_decode_single_tlv(buf, buf_len, &seq) != 0 || seq.tag != 0x30)
  {
    return;
  }

  while (seq.length > 0)
  {
    used = ndpi_asn1_ber_decode_tlv(seq.value, seq.length, &field);
    if (used < 0 || field.tag > 0xA2)
    {
      return;
    }

    if (field.tag == 0xA0)
    {
      /* Constrained delegation: the client name of the reply is the one of
         the additional ticket (i.e. the user), not the requester one.
         NOTE: additional-tickets without this option are user-to-user */
      if (msg_type == KRB_MSG_TYPE_TGS_REQ &&
          krb_kdc_option_is_set(field.value, field.length, KRB_KDC_OPT_CNAME_IN_ADDL_TKT))
      {
        krb->s4u = NDPI_KERBEROS_S4U2PROXY;
      }
    } else if (field.tag == 0xA1) {
      krb_parse_cname(krb, field.value, field.length, 0);
    } else if (field.tag == 0xA2) {
      krb_parse_realm(krb, field.value, field.length, 0);
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
  int hdr_len = ndpi_asn1_ber_decode_header(buf, buf_len, &tag, &length);

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

  With mode KRB_PARSE_PREFIX/KRB_PARSE_PREFIX_FINAL, buf holds only the
  beginning of the message: the fields are parsed up to the first incomplete
  one.

  Returns the message type, 0 if more data is needed (only with
  KRB_PARSE_PREFIX) or -1
*/
static int krb_parse(struct ndpi_detection_module_struct * const ndpi_struct,
                     struct ndpi_kerberos_metadata * const krb,
                     const u_int8_t *buf, u_int32_t buf_len,
                     u_int8_t mode)
{
  struct ndpi_asn1_ber_tlv app, seq, field;
  u_int8_t msg_type, pvno_idx, idx, pvno_found = 0, msg_type_found = 0, overwrite;
  u_int8_t incomplete = 0, last_idx = 0;
  int32_t value;
  int used;

  if (mode == KRB_PARSE_FULL)
  {
    if (ndpi_asn1_ber_decode_single_tlv(buf, buf_len, &app) != 0 ||
        (app.tag & 0xE0) != 0x60 /* Application Constructed */ ||
        ndpi_asn1_ber_decode_single_tlv(app.value, app.length, &seq) != 0 ||
        seq.tag != 0x30)
    {
      return -1;
    }
  } else {
    int app_hdr, seq_hdr;
    u_int32_t avail;

    app_hdr = ndpi_asn1_ber_decode_header(buf, buf_len, &app.tag, &app.length);
    if (app_hdr < 0)
    {
      /* The header is at most 6 bytes (see ndpi_asn1_ber_decode_header) */
      return (mode == KRB_PARSE_PREFIX && buf_len < 6) ? 0 : -1;
    }
    if ((app.tag & 0xE0) != 0x60 /* Application Constructed */)
    {
      return -1;
    }
    avail = ndpi_min(app.length, buf_len - app_hdr);

    seq_hdr = ndpi_asn1_ber_decode_header(&buf[app_hdr], avail, &seq.tag, &seq.length);
    if (seq_hdr < 0)
    {
      return (mode == KRB_PARSE_PREFIX && avail < 6) ? 0 : -1;
    }
    if (seq.tag != 0x30 || (u_int32_t)seq_hdr + seq.length > app.length)
    {
      return -1;
    }
    seq.value = &buf[app_hdr + seq_hdr];
    if (seq.length > avail - seq_hdr)
    {
      /* Only the beginning of the fields is available */
      seq.length = avail - seq_hdr;
      incomplete = 1;
    }
  }

  msg_type = app.tag & 0x1F;
  if (!krb_is_valid_msg_type(msg_type))
  {
    return -1;
  }
  pvno_idx = krb_is_request(msg_type) ? 1 : 0;

  while (seq.length > 0)
  {
    used = ndpi_asn1_ber_decode_tlv(seq.value, seq.length, &field);
    if (used < 0 || (field.tag & 0xE0) != 0xA0 /* Context-specific Constructed */)
    {
      break;
    }
    seq.value += used;
    seq.length -= used;
    idx = field.tag & 0x1F;
    last_idx = idx;

    if (idx == pvno_idx)
    {
      if (ndpi_asn1_ber_decode_int(field.value, field.length, &value) != 0 || value != 5)
      {
        return -1;
      }
      pvno_found = 1;
      continue;
    }
    if (idx == pvno_idx + 1)
    {
      if (ndpi_asn1_ber_decode_int(field.value, field.length, &value) != 0 || value != msg_type)
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
        /* Only the first request is exported (see below) */
        if (krb->req_msg_type != 0)
        {
          break;
        }

        if (idx == 3 && msg_type == KRB_MSG_TYPE_TGS_REQ)
        {
          krb_parse_tgs_req_padata(krb, field.value, field.length);
        } else if (idx == 4) {
          krb_parse_req_body(krb, field.value, field.length, msg_type);
        }
        break;

      case KRB_MSG_TYPE_AS_REP:
      case KRB_MSG_TYPE_TGS_REP:
        /* Only the first reply is exported (see below) */
        overwrite = (krb->rep_msg_type == 0);

        if (idx == 3)
        {
          krb_parse_realm(krb, field.value, field.length, overwrite);
        } else if (idx == 4) {
          krb_parse_cname(krb, field.value, field.length, overwrite);
        }
        break;

      case KRB_MSG_TYPE_ERROR:
        if (idx == 6)
        {
          if (ndpi_asn1_ber_decode_int(field.value, field.length, &value) == 0 &&
              krb->rep_msg_type == 0)
          {
            krb->error_code = value;
          }
        } else if (idx == 7 || idx == 9) {
          krb_parse_realm(krb, field.value, field.length, 0);
        } else if (idx == 8) {
          krb_parse_cname(krb, field.value, field.length, 0);
        }
        break;

      default:
        break;
    }
  }

  if (incomplete && mode == KRB_PARSE_PREFIX)
  {
    /* The names are in the fields up to cname [4] (KDC-REP) or sname [10]
       (KRB-ERROR) */
    if (!pvno_found || !msg_type_found ||
        ((msg_type == KRB_MSG_TYPE_AS_REP || msg_type == KRB_MSG_TYPE_TGS_REP) && last_idx < 4) ||
        (msg_type == KRB_MSG_TYPE_ERROR && last_idx < 10) ||
        krb_is_request(msg_type) || msg_type == KRB_MSG_TYPE_AP_REQ)
    {
      return 0;
    }
  }

  if (!pvno_found || !msg_type_found)
  {
    return -1;
  }

  /* Only the first request and the first reply are exported */
  if (krb_is_request(msg_type))
  {
    if (krb->req_msg_type == 0)
    {
      krb->req_msg_type = msg_type;
    }
  } else if (msg_type != KRB_MSG_TYPE_AP_REQ) {
    if (krb->rep_msg_type == 0)
    {
      krb->rep_msg_type = msg_type;
    }
  }

  NDPI_LOG_DBG(ndpi_struct,
               "[msg-type: %u][Kerberos Hostname,Domain,Username][%s,%s,%s]\n",
               msg_type, krb->hostname, krb->domain,
               krb->username);

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

/*
  Returns the type of the message found, 0 if we need more data or -1 if it is not Kerberos.
  reply_expected: the flow has already been detected (by a request): a message
  split in several segments is a reply, whose beginning only is needed
*/
static int krb_process_packet(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow,
			      struct ndpi_kerberos_metadata *krb,
			      u_int8_t reply_expected) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len, kerberos_len;
  int msg_type;

#ifdef KERBEROS_DEBUG
  printf("\n[Kerberos] Process packet [len: %u]\n", packet->payload_packet_len);
#endif

  if(flow->metadata.kerberos_buf.pktbuf != NULL) {
    u_int missing = flow->metadata.kerberos_buf.pktbuf_maxlen - flow->metadata.kerberos_buf.pktbuf_currlen;

    if(flow->metadata.kerberos_buf.prefix) {
      /* Beginning of a reply: whatever exceeds the buffer is not needed */
      u_int len = ndpi_min(payload_len, missing);
      u_int8_t final;

      memcpy(&flow->metadata.kerberos_buf.pktbuf[flow->metadata.kerberos_buf.pktbuf_currlen], payload, len);
      flow->metadata.kerberos_buf.pktbuf_currlen += len;
      final = (flow->metadata.kerberos_buf.pktbuf_currlen == flow->metadata.kerberos_buf.pktbuf_maxlen);

      msg_type = krb_parse(ndpi_struct, krb,
                           (const u_int8_t *)&flow->metadata.kerberos_buf.pktbuf[4],
                           flow->metadata.kerberos_buf.pktbuf_currlen - 4,
                           final ? KRB_PARSE_PREFIX_FINAL : KRB_PARSE_PREFIX);
      if(msg_type == 0)
	return 0;

      krb_free_buf(flow);
      return msg_type;
    }

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

    if(kerberos_len < payload_len)
      return -1;

    if(reply_expected && kerberos_len > payload_len) {
      if(kerberos_len >= KRB_MAX_REPLY_LEN)
	return -1;

      /* Usually the first segment is enough */
      msg_type = krb_parse(ndpi_struct, krb, payload, payload_len, KRB_PARSE_PREFIX);
      if(msg_type != 0)
	return msg_type;

      flow->metadata.kerberos_buf.pktbuf_maxlen = ndpi_min(kerberos_len, KRB_MAX_BUF_LEN) + 4;
      flow->metadata.kerberos_buf.pktbuf = (char*)ndpi_malloc(flow->metadata.kerberos_buf.pktbuf_maxlen);
      if(flow->metadata.kerberos_buf.pktbuf == NULL)
	return -1;

      flow->metadata.kerberos_buf.prefix = 1;
      memcpy(flow->metadata.kerberos_buf.pktbuf, payload-4, payload_len+4);
      flow->metadata.kerberos_buf.pktbuf_currlen = payload_len+4;
      return 0;
    }

    if(kerberos_len >= KRB_MAX_BUF_LEN)
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
      flow->metadata.kerberos_buf.prefix = 0;
      memcpy(flow->metadata.kerberos_buf.pktbuf, payload-4, payload_len+4);
      flow->metadata.kerberos_buf.pktbuf_currlen = payload_len+4;
#ifdef KERBEROS_DEBUG
      printf("[Kerberos] Allocated %u bytes\n", flow->metadata.kerberos_buf.pktbuf_maxlen);
#endif
      return 0;
    }
  }

  msg_type = krb_parse(ndpi_struct, krb, payload, payload_len, KRB_PARSE_FULL);

#ifdef KERBEROS_DEBUG
  printf("[Kerberos] [msg-type: %d]\n", msg_type);
#endif

  krb_free_buf(flow);

  return msg_type;
}

static void krb_message_found(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow, int msg_type) {
  if(krb_is_request(msg_type) && ndpi_struct->cfg.kerberos_max_packets_extra_dissection > 0) {
    /* Looking for the reply (it may be split into multiple segments) */
    flow->core.max_extra_packets_to_check = ndpi_struct->cfg.kerberos_max_packets_extra_dissection;
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
  /*
    Metadata is parsed into a local copy, seeded with what previous messages of
    this flow already committed, and written back to the shared union only once
    the flow has actually been classified as Kerberos. A partially parsed (and
    then rejected) message must not leave any data behind: if the flow later
    ends up tagged with another protocol (e.g. the by-port guess at detection
    give-up), stale bytes in the metadata.protos union would be interpreted
    with the wrong union member (type confusion).
  */
  struct ndpi_kerberos_metadata krb = flow->metadata.protos.kerberos;
  int msg_type;

  if((sport != KERBEROS_PORT) && (dport != KERBEROS_PORT)) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  NDPI_LOG_DBG(ndpi_struct, "search KERBEROS\n");

  msg_type = krb_process_packet(ndpi_struct, flow, &krb, 0);
  if(msg_type < 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }
  if(msg_type == 0)
    return;

  ndpi_int_kerberos_add_connection(ndpi_struct, flow);
  /* Classified as Kerberos: now it is safe to commit the metadata */
  flow->metadata.protos.kerberos = krb;
  krb_message_found(ndpi_struct, flow, msg_type);
}

static int ndpi_search_kerberos_extra(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  /* The flow is already classified as Kerberos here; still parse into a local
     copy and commit it only on a successfully decoded message */
  struct ndpi_kerberos_metadata krb = flow->metadata.protos.kerberos;
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
  msg_type = krb_process_packet(ndpi_struct, flow, &krb, 1);
  if(msg_type > 0) {
    flow->metadata.protos.kerberos = krb;
    krb_message_found(ndpi_struct, flow, msg_type);
  }

  /* Possibly more processing */
  return flow->core.extra_packets_func != NULL;
}

/* ********************************** */

const char *ndpi_kerberos_msg_type2str(u_int8_t msg_type) {
  switch(msg_type) {
  case 10: return("AS-REQ");
  case 11: return("AS-REP");
  case 12: return("TGS-REQ");
  case 13: return("TGS-REP");
  case 30: return("KRB-ERROR");
  default: return("Unknown");
  }
}

/* ********************************** */

/* Name type of a PrincipalName (RFC 4120 section 6.2, RFC 6111, MS-KILE) */
const char *ndpi_kerberos_name_type2str(int32_t name_type) {
  switch(name_type) {
  case 0:    return("NT-UNKNOWN");
  case 1:    return("NT-PRINCIPAL");
  case 2:    return("NT-SRV-INST");
  case 3:    return("NT-SRV-HST");
  case 4:    return("NT-SRV-XHST");
  case 5:    return("NT-UID");
  case 6:    return("NT-X500-PRINCIPAL");
  case 7:    return("NT-SMTP-NAME");
  case 10:   return("NT-ENTERPRISE");
  case 11:   return("NT-WELLKNOWN");
  case -128: return("NT-MS-PRINCIPAL");
  case -129: return("NT-MS-PRINCIPAL-AND-ID");
  case -130: return("NT-ENT-PRINCIPAL-AND-ID");
  default:   return("Unknown");
  }
}

/* ********************************** */

/* Error code of a KRB-ERROR (RFC 4120 section 7.5.9, RFC 4556, RFC 6113) */
const char *ndpi_kerberos_error2str(int32_t error_code) {
  switch(error_code) {
  case 0:  return("KDC_ERR_NONE");
  case 1:  return("KDC_ERR_NAME_EXP");
  case 2:  return("KDC_ERR_SERVICE_EXP");
  case 3:  return("KDC_ERR_BAD_PVNO");
  case 4:  return("KDC_ERR_C_OLD_MAST_KVNO");
  case 5:  return("KDC_ERR_S_OLD_MAST_KVNO");
  case 6:  return("KDC_ERR_C_PRINCIPAL_UNKNOWN");
  case 7:  return("KDC_ERR_S_PRINCIPAL_UNKNOWN");
  case 8:  return("KDC_ERR_PRINCIPAL_NOT_UNIQUE");
  case 9:  return("KDC_ERR_NULL_KEY");
  case 10: return("KDC_ERR_CANNOT_POSTDATE");
  case 11: return("KDC_ERR_NEVER_VALID");
  case 12: return("KDC_ERR_POLICY");
  case 13: return("KDC_ERR_BADOPTION");
  case 14: return("KDC_ERR_ETYPE_NOSUPP");
  case 15: return("KDC_ERR_SUMTYPE_NOSUPP");
  case 16: return("KDC_ERR_PADATA_TYPE_NOSUPP");
  case 17: return("KDC_ERR_TRTYPE_NOSUPP");
  case 18: return("KDC_ERR_CLIENT_REVOKED");
  case 19: return("KDC_ERR_SERVICE_REVOKED");
  case 20: return("KDC_ERR_TGT_REVOKED");
  case 21: return("KDC_ERR_CLIENT_NOTYET");
  case 22: return("KDC_ERR_SERVICE_NOTYET");
  case 23: return("KDC_ERR_KEY_EXPIRED");
  case 24: return("KDC_ERR_PREAUTH_FAILED");
  case 25: return("KDC_ERR_PREAUTH_REQUIRED");
  case 26: return("KDC_ERR_SERVER_NOMATCH");
  case 27: return("KDC_ERR_MUST_USE_USER2USER");
  case 28: return("KDC_ERR_PATH_NOT_ACCEPTED");
  case 29: return("KDC_ERR_SVC_UNAVAILABLE");
  case 31: return("KRB_AP_ERR_BAD_INTEGRITY");
  case 32: return("KRB_AP_ERR_TKT_EXPIRED");
  case 33: return("KRB_AP_ERR_TKT_NYV");
  case 34: return("KRB_AP_ERR_REPEAT");
  case 35: return("KRB_AP_ERR_NOT_US");
  case 36: return("KRB_AP_ERR_BADMATCH");
  case 37: return("KRB_AP_ERR_SKEW");
  case 38: return("KRB_AP_ERR_BADADDR");
  case 39: return("KRB_AP_ERR_BADVERSION");
  case 40: return("KRB_AP_ERR_MSG_TYPE");
  case 41: return("KRB_AP_ERR_MODIFIED");
  case 42: return("KRB_AP_ERR_BADORDER");
  case 43: return("KRB_AP_ERR_ILL_CR_TKT");
  case 44: return("KRB_AP_ERR_BADKEYVER");
  case 45: return("KRB_AP_ERR_NOKEY");
  case 46: return("KRB_AP_ERR_MUT_FAIL");
  case 47: return("KRB_AP_ERR_BADDIRECTION");
  case 48: return("KRB_AP_ERR_METHOD");
  case 49: return("KRB_AP_ERR_BADSEQ");
  case 50: return("KRB_AP_ERR_INAPP_CKSUM");
  case 51: return("KRB_AP_PATH_NOT_ACCEPTED");
  case 52: return("KRB_ERR_RESPONSE_TOO_BIG");
  case 60: return("KRB_ERR_GENERIC");
  case 61: return("KRB_ERR_FIELD_TOOLONG");
  case 62: return("KDC_ERR_CLIENT_NOT_TRUSTED");
  case 63: return("KDC_ERR_KDC_NOT_TRUSTED");
  case 64: return("KDC_ERR_INVALID_SIG");
  case 65: return("KDC_ERR_KEY_TOO_WEAK");
  case 66: return("KDC_ERR_CERTIFICATE_MISMATCH");
  case 67: return("KRB_AP_ERR_NO_TGT");
  case 68: return("KDC_ERR_WRONG_REALM");
  case 69: return("KRB_AP_ERR_USER_TO_USER_REQUIRED");
  case 70: return("KDC_ERR_CANT_VERIFY_CERTIFICATE");
  case 71: return("KDC_ERR_INVALID_CERTIFICATE");
  case 72: return("KDC_ERR_REVOKED_CERTIFICATE");
  case 73: return("KDC_ERR_REVOCATION_STATUS_UNKNOWN");
  case 74: return("KDC_ERR_REVOCATION_STATUS_UNAVAILABLE");
  case 75: return("KDC_ERR_CLIENT_NAME_MISMATCH");
  case 76: return("KDC_ERR_KDC_NAME_MISMATCH");
  case 77: return("KDC_ERR_INCONSISTENT_KEY_PURPOSE");
  case 78: return("KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED");
  case 79: return("KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED");
  case 80: return("KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED");
  case 81: return("KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED");
  case 90: return("KDC_ERR_PREAUTH_EXPIRED");
  case 91: return("KDC_ERR_MORE_PREAUTH_DATA_REQUIRED");
  case 92: return("KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET");
  case 93: return("KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS");
  default: return("Unknown");
  }
}

/* ********************************** */

/* NULL if the request is not an S4U one */
const char *ndpi_kerberos_s4u2str(u_int8_t s4u) {
  switch(s4u) {
  case NDPI_KERBEROS_S4U_NONE:   return(NULL);
  case NDPI_KERBEROS_S4U2SELF:   return("S4U2Self");
  case NDPI_KERBEROS_S4U2PROXY:  return("S4U2Proxy");
  default:                       return("Unknown");
  }
}

/* ********************************** */

/* The KDC issued the requested ticket (AS-REP or TGS-REP) */
int ndpi_kerberos_reply_ok(const struct ndpi_kerberos_metadata *krb) {
  return(krb != NULL &&
         (krb->rep_msg_type == 11 /* AS-REP */ || krb->rep_msg_type == 13 /* TGS-REP */));
}

/* ********************************** */

/* Name of the error of a KRB-ERROR reply; NULL if the reply is not an error */
const char *ndpi_kerberos_reply_error(const struct ndpi_kerberos_metadata *krb) {
  if(krb == NULL || krb->rep_msg_type != 30 /* KRB-ERROR */)
    return(NULL);

  return(ndpi_kerberos_error2str(krb->error_code));
}

/* ********************************** */

/*
  Client principal as "user@realm", or "host$@realm" for a machine (the form of
  its account name). The realm is omitted if unknown.
  An enterprise name (e.g. "user@upn.suffix") is used as it is if it ends with
  the realm, otherwise its '@' are escaped (RFC 1964 string form):
  "user\@upn.suffix@realm".
  Return the length of the name (0 if there is no name)
*/
int ndpi_kerberos_client_name(const struct ndpi_kerberos_metadata *krb,
                              char *buf, u_int buf_len) {
  const char *name, *suffix = "", *at;
  u_int len = 0, i;
  int has_realm;

  if(buf == NULL || buf_len == 0)
    return(0);
  buf[0] = '\0';

  if(krb == NULL)
    return(0);

  if(krb->username[0] != '\0')
    name = krb->username;
  else if(krb->hostname[0] != '\0')
    name = krb->hostname, suffix = "$";
  else
    return(0);

  has_realm = (krb->domain[0] != '\0');
  at = strrchr(name, '@');
  if(at != NULL && has_realm && strcasecmp(at + 1, krb->domain) == 0)
    has_realm = 0; /* Enterprise name ending with the realm */

  for(i = 0; name[i] != '\0' && len + 1 < buf_len; i++) {
    if(name[i] == '@' && has_realm) {
      if(len + 2 >= buf_len)
        break;
      buf[len++] = '\\';
    }
    buf[len++] = name[i];
  }
  buf[len] = '\0';

  if(has_realm)
    ndpi_snprintf(&buf[len], buf_len - len, "%s@%s", suffix, krb->domain);
  else
    ndpi_snprintf(&buf[len], buf_len - len, "%s", suffix);

  return((int)strlen(buf));
}

/* ********************************** */

/* Serialize the metadata (the caller opens/closes the enclosing block, if any) */
int ndpi_kerberos2json(ndpi_serializer *serializer, const struct ndpi_kerberos_metadata *krb) {
  const char *s4u;

  if(serializer == NULL || krb == NULL)
    return(-1);

  ndpi_serialize_string_string(serializer, "hostname", krb->hostname);
  ndpi_serialize_string_string(serializer, "domain", krb->domain);
  ndpi_serialize_string_string(serializer, "username", krb->username);
  if(krb->hostname_truncated)
    ndpi_serialize_string_boolean(serializer, "hostname_truncated", 1);
  if(krb->domain_truncated)
    ndpi_serialize_string_boolean(serializer, "domain_truncated", 1);
  if(krb->username_truncated)
    ndpi_serialize_string_boolean(serializer, "username_truncated", 1);
  if(krb->name_type_found)
    ndpi_serialize_string_int32(serializer, "name_type", krb->name_type);
  if((s4u = ndpi_kerberos_s4u2str(krb->s4u)) != NULL)
    ndpi_serialize_string_string(serializer, "s4u", s4u);
  if(krb->req_msg_type != 0)
    ndpi_serialize_string_uint32(serializer, "request_type", krb->req_msg_type);
  if(krb->rep_msg_type != 0) {
    ndpi_serialize_string_uint32(serializer, "response_type", krb->rep_msg_type);
    ndpi_serialize_string_boolean(serializer, "response_ok", ndpi_kerberos_reply_ok(krb));
    if(krb->rep_msg_type == 30 /* KRB-ERROR */)
      ndpi_serialize_string_int32(serializer, "error_code", krb->error_code);
  }

  return(0);
}

void init_kerberos_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("Kerberos", ndpi_struct,
                     ndpi_search_kerberos,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                      DISSECTOR_LICENSE_LGPL,
                      1, NDPI_PROTOCOL_KERBEROS);
}
