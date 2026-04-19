/*
 * ipsec.c
 *
 * Copyright (C) 2022-23 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_IPSEC

#include "ndpi_api.h"
#include "ndpi_private.h"

enum isakmp_type {
  ISAKMP_INVALID = 0,
  ISAKMP_MALFORMED,
  ISAKMP_V1,
  ISAKMP_V2,
};

/* IKEv2 Exchange Types (RFC 7296 §3.1) */
#define IKEV2_EXCHANGE_SA_INIT        34
#define IKEV2_EXCHANGE_IKE_AUTH       35
#define IKEV2_EXCHANGE_CREATE_CHILD   36
#define IKEV2_EXCHANGE_INFORMATIONAL  37

/* IKEv2 Payload Types (RFC 7296 §3.2) */
#define IKEV2_PAYLOAD_SA    33
#define IKEV2_PAYLOAD_KE    34
#define IKEV2_PAYLOAD_NONCE 40

/* IKEv2 Transform Types (RFC 7296 §3.3.2) */
#define IKEV2_TRANSFORM_ENCR  1
#define IKEV2_TRANSFORM_PRF   2
#define IKEV2_TRANSFORM_INTEG 3
#define IKEV2_TRANSFORM_DH    4
#define IKEV2_TRANSFORM_ESN   5

/* Transform Attribute Type (RFC 7296 §3.3.5) */
#define IKEV2_ATTR_KEY_LENGTH 14

static void ndpi_search_ipsec(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow);

/* ********************************************* */

/*
 * Parse transforms within an IKEv2 proposal substructure.
 * Fills *prop with the first instance of each transform type found.
 * xform_start points to the first transform, prop_end is the byte past the proposal.
 */
static void ikev2_parse_transforms(const u_int8_t *payload, u_int16_t xform_start,
                                   u_int16_t prop_end, u_int8_t num_transforms,
                                   struct ndpi_ipsec_proposal *prop) {
  u_int16_t off = xform_start;

  for (u_int8_t t = 0; t < num_transforms && off < prop_end; t++) {
    /* Transform substructure header: 8 bytes minimum */
    if (off + 8 > prop_end) break;

    u_int16_t xform_len  = ntohs(get_u_int16_t(payload, off + 2));
    u_int8_t  xform_type = payload[off + 4];
    u_int16_t xform_id   = ntohs(get_u_int16_t(payload, off + 6));

    if (xform_len < 8 || off + xform_len > prop_end) break;

    /* Scan attributes inside this transform (key length, etc.) */
    u_int16_t key_bits = 0;
    u_int16_t attr_off = off + 8;
    u_int16_t attr_end = off + xform_len;

    while (attr_off + 4 <= attr_end) {
      u_int16_t attr_hdr  = ntohs(get_u_int16_t(payload, attr_off));
      int       tv_format = (attr_hdr & 0x8000) != 0;
      u_int16_t attr_type = attr_hdr & 0x7FFF;

      if (tv_format) {
        u_int16_t attr_val = ntohs(get_u_int16_t(payload, attr_off + 2));
        if (attr_type == IKEV2_ATTR_KEY_LENGTH)
          key_bits = attr_val;
        attr_off += 4;
      } else {
        u_int16_t attr_len = ntohs(get_u_int16_t(payload, attr_off + 2));
        attr_off += 4 + attr_len;
      }
    }

    /* Store first occurrence of each transform type; print for debugging */
    switch (xform_type) {
      case IKEV2_TRANSFORM_ENCR:
        if (prop->encr_alg == 0) {
          prop->encr_alg      = xform_id;
          prop->encr_key_bits = key_bits;
        }

#ifdef IPSEC_DEBUG
	if (key_bits > 0)
          printf("[IKEv2 SA_INIT]     ENCR : %s (%u bits)\n", ndpi_ikev2_encr_name(xform_id), key_bits);
        else
          printf("[IKEv2 SA_INIT]     ENCR : %s\n", ndpi_ikev2_encr_name(xform_id));
#endif
        break;

      case IKEV2_TRANSFORM_PRF:
        if (prop->prf_alg == 0)
          prop->prf_alg = xform_id;

#ifdef IPSEC_DEBUG
        printf("[IKEv2 SA_INIT]     PRF  : %s\n", ndpi_ikev2_prf_name(xform_id));
#endif
        break;

      case IKEV2_TRANSFORM_INTEG:
        if (prop->integ_alg == 0)
          prop->integ_alg = xform_id;

#ifdef IPSEC_DEBUG
	printf("[IKEv2 SA_INIT]     INTEG: %s\n", ndpi_ikev2_integ_name(xform_id));
#endif
        break;

      case IKEV2_TRANSFORM_DH:
        if (prop->dh_group == 0)
          prop->dh_group = xform_id;
#ifdef IPSEC_DEBUG
        printf("[IKEv2 SA_INIT]     DH   : %s (%u)\n", ndpi_ikev2_dh_name(xform_id), xform_id);
#endif
        break;

      case IKEV2_TRANSFORM_ESN:
        prop->esn = (u_int8_t)xform_id;

#ifdef IPSEC_DEBUG
        printf("[IKEv2 SA_INIT]     ESN  : %s\n", xform_id == 0 ? "No ESN" : "ESN");
#endif
        break;

      default:
#ifdef IPSEC_DEBUG
        printf("[IKEv2 SA_INIT]     Transform type=%u id=%u\n", xform_type, xform_id);
#endif
        break;
    }

    off += xform_len;
  }
}

/* ********************************************* */

/*
 * Dissect IKEv2 IKE_SA_INIT payloads starting after the 28-byte IKEv2 header.
 * Populates flow->protos.ipsec with the exchange type and up to
 * NDPI_IKEV2_MAX_PROPOSALS SA proposals, each with its crypto attributes.
 */
static void ndpi_dissect_ikev2_sa_init(struct ndpi_flow_struct *flow,
                                       const u_int8_t *payload, u_int16_t payload_len,
                                       u_int16_t isakmp_offset) {
  /* IKEv2 fixed header is 28 bytes */
  u_int16_t off          = isakmp_offset + 28;
  u_int8_t  next_payload = payload[isakmp_offset + 16];

  flow->protos.ipsec.version = payload[isakmp_offset + 17];
  flow->protos.ipsec.exchange_type = payload[isakmp_offset + 18];
  flow->protos.ipsec.num_proposals = 0;

#ifdef IPSEC_DEBUG
  printf("[IKEv2 SA_INIT] Dissecting IKE_SA_INIT (offset=%u, total=%u)\n",
         isakmp_offset, payload_len);
#endif

  while (next_payload != 0 && off + 4 <= payload_len) {
    u_int8_t  curr_payload = next_payload;
    u_int16_t plen         = ntohs(get_u_int16_t(payload, off + 2));

    next_payload = payload[off];   /* next payload type from generic header */

    if (plen < 4 || off + plen > payload_len) break;

    if (curr_payload == IKEV2_PAYLOAD_SA) {
      /* SA payload body starts 4 bytes in (past generic payload header) */
      u_int16_t sa_off = off + 4;
      u_int16_t sa_end = off + plen;

      while (sa_off + 8 <= sa_end) {
        u_int8_t  last_prop      = payload[sa_off];   /* 0=last, 2=more */
        u_int16_t prop_len       = ntohs(get_u_int16_t(payload, sa_off + 2));
#ifdef IPSEC_DEBUG
        u_int8_t  prop_num       = payload[sa_off + 4];
#endif
        u_int8_t  proto_id       = payload[sa_off + 5];
        u_int8_t  spi_size       = payload[sa_off + 6];
        u_int8_t  num_transforms = payload[sa_off + 7];

        if (prop_len < 8 || sa_off + prop_len > sa_end) break;

#ifdef IPSEC_DEBUG
        const char *proto_str = (proto_id == 1) ? "IKE"
                              : (proto_id == 2) ? "AH"
                              : (proto_id == 3) ? "ESP"
                              : "UNKNOWN";

        printf("[IKEv2 SA_INIT]   Proposal #%u  proto=%s  transforms=%u\n",
               prop_num, proto_str, num_transforms);
#endif

        u_int8_t idx = flow->protos.ipsec.num_proposals;

        if (idx < NDPI_IKEV2_MAX_PROPOSALS) {
          struct ndpi_ipsec_proposal *prop = &flow->protos.ipsec.proposal[idx];
          prop->proto_id       = proto_id;
          prop->num_transforms = num_transforms;
          prop->encr_alg       = 0;
          prop->encr_key_bits  = 0;
          prop->prf_alg        = 0;
          prop->integ_alg      = 0;
          prop->dh_group       = 0;
          prop->esn            = 0;

          u_int16_t xform_start = sa_off + 8 + spi_size;
          u_int16_t prop_end    = sa_off + prop_len;

          ikev2_parse_transforms(payload, xform_start, prop_end, num_transforms, prop);

          flow->protos.ipsec.num_proposals = idx + 1;
        }

        if (last_prop == 0) break;   /* no more proposals */
        sa_off += prop_len;
      }
    }

    off += plen;
  }
}

/* ************************************************************************ */

static int search_ipsec_again(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow) {
  ndpi_search_ipsec(ndpi_struct, flow);

  if(flow->protos.ipsec.num_proposals > 0) {
    /* stop extra processing */
    flow->extra_packets_func = NULL; /* We're good now */
    return(0);
  }

  /* Possibly more processing */
  return(1);
}

/* ********************************************* */

static void ndpi_int_ipsec_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                          struct ndpi_flow_struct * const flow,
                                          enum isakmp_type isakmp_type) {
  switch (isakmp_type)
  {
    case ISAKMP_INVALID:
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
      return;
    case ISAKMP_MALFORMED:
      NDPI_LOG_INFO(ndpi_struct, "found malformed ISAKMP (UDP)\n");
      ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid IPSec/ISAKMP Header");
      break;
    case ISAKMP_V1:
      NDPI_LOG_INFO(ndpi_struct, "found ISAKMPv1 (UDP)\n");
      break;
    case ISAKMP_V2:
      NDPI_LOG_INFO(ndpi_struct, "found ISAKMPv2 (UDP)\n");
      break;
  }

  if(flow->protos.ipsec.num_proposals == 0) {
    flow->max_extra_packets_to_check = 6;
    flow->extra_packets_func = search_ipsec_again;
  }

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_IPSEC,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ********************************************* */

static enum isakmp_type ndpi_int_check_ports(struct ndpi_packet_struct const * const packet) {
  u_int16_t sport = ntohs(packet->udp->source);
  u_int16_t dport = ntohs(packet->udp->dest);

  /*
   * If packet matches default IPSec/ISAKMP ports, it is most likely malformed,
   * not IPSec/ISAKMP otherwise.
   */
  if (sport == 500 || dport == 500 ||
      sport == 4500 || dport == 4500)
  {
    return ISAKMP_MALFORMED;
  }

  return ISAKMP_INVALID;
}

/* ********************************************* */

static enum isakmp_type ndpi_int_check_isakmp_v1(struct ndpi_packet_struct const * const packet,
                                                 u_int16_t isakmp_offset, enum isakmp_type isakmp_type) {
  /* Next payload type */
  if (packet->payload[isakmp_offset + 16] >= 14 && packet->payload[isakmp_offset + 16] <= 127)
  {
    return ndpi_int_check_ports(packet);
  }

  /* Exchange Type */
  if (packet->payload[isakmp_offset + 18] >= 6 && packet->payload[isakmp_offset + 18] < 31)
  {
    return ndpi_int_check_ports(packet);
  }

  /* Flags */
  if (packet->payload[isakmp_offset + 19] >= 8)
  {
    return ndpi_int_check_ports(packet);
  }

  return isakmp_type;
}

/* ********************************************* */

static enum isakmp_type ndpi_int_check_isakmp_v2(struct ndpi_packet_struct const * const packet,
                                                 u_int16_t isakmp_offset, enum isakmp_type isakmp_type) {
  /* Next payload type */
  if ((packet->payload[isakmp_offset + 16] > 0 && packet->payload[isakmp_offset + 16] <= 32) ||
      (packet->payload[isakmp_offset + 16] >= 49 && packet->payload[isakmp_offset + 16] <= 127))
  {
    return ndpi_int_check_ports(packet);
  }

  /* Exchange Type */
  if ((packet->payload[isakmp_offset + 18] <= 33) ||
      (packet->payload[isakmp_offset + 18] >= 38 && packet->payload[isakmp_offset + 18] <= 239))
  {
    return ndpi_int_check_ports(packet);
  }

  /* Flags */
  if ((packet->payload[isakmp_offset + 19] & 0xC7) != 0)
  {
    return ndpi_int_check_ports(packet);
  }

  return isakmp_type;
}

/* ********************************************* */

static void ndpi_search_ipsec(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  u_int16_t isakmp_offset = 0;
  enum isakmp_type isakmp_type = ISAKMP_INVALID;

  NDPI_LOG_DBG(ndpi_struct, "search IPSEC (UDP)\n");

  if (packet->payload_packet_len < 28)
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* check for non-ESP marker required for ISAKMP over UDP */
  if (get_u_int32_t(packet->payload, 0) == 0x00000000)
  {
    isakmp_offset = 4;
    if (packet->payload_packet_len < 32)
    {
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
      return;
    }
  }

  if (packet->payload[isakmp_offset + 17] != 0x20 /* Major Version 2 */)
  {
    if (packet->payload[isakmp_offset + 17] != 0x10 /* Major Version 1 */)
    {
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
      return;
    } else {
      /* Version 1 is obsolete, but still used by some embedded devices. */
      isakmp_type = ISAKMP_V1;
    }
  } else {
    isakmp_type = ISAKMP_V2;
  }

  if (ntohl(get_u_int32_t(packet->payload, isakmp_offset + 24)) != (u_int32_t)packet->payload_packet_len - isakmp_offset)
  {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if (isakmp_type == ISAKMP_V1)
  {
    isakmp_type = ndpi_int_check_isakmp_v1(packet, isakmp_offset, isakmp_type);
  } else {
    isakmp_type = ndpi_int_check_isakmp_v2(packet, isakmp_offset, isakmp_type);

    /* Dissect IKE_SA_INIT payloads to extract crypto algorithm proposals. */
    if (isakmp_type == ISAKMP_V2 &&
        packet->payload[isakmp_offset + 18] == IKEV2_EXCHANGE_SA_INIT)
    {
      ndpi_dissect_ikev2_sa_init(flow, packet->payload, packet->payload_packet_len, isakmp_offset);
    }
  }

  ndpi_int_ipsec_add_connection(ndpi_struct, flow, isakmp_type);
}

/* ********************************************* */

void init_ipsec_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("IPSec", ndpi_struct,
			  ndpi_search_ipsec,
			  NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
			  1, NDPI_PROTOCOL_IPSEC);
}
