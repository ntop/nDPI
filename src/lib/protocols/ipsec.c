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

static void ndpi_int_ipsec_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                          struct ndpi_flow_struct * const flow,
                                          enum isakmp_type isakmp_type)
{
  switch (isakmp_type)
  {
    case ISAKMP_INVALID:
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
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

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_IPSEC,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static enum isakmp_type ndpi_int_check_ports(struct ndpi_packet_struct const * const packet)
{
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

static enum isakmp_type ndpi_int_check_isakmp_v1(struct ndpi_packet_struct const * const packet,
                                                 u_int16_t isakmp_offset, enum isakmp_type isakmp_type)
{
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

static enum isakmp_type ndpi_int_check_isakmp_v2(struct ndpi_packet_struct const * const packet,
                                                 u_int16_t isakmp_offset, enum isakmp_type isakmp_type)
{
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

static void ndpi_search_ipsec(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  u_int16_t isakmp_offset = 0;
  enum isakmp_type isakmp_type = ISAKMP_INVALID;

  NDPI_LOG_DBG(ndpi_struct, "search IPSEC (UDP)\n");

  if (packet->payload_packet_len < 28)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /* check for non-ESP marker required for ISAKMP over UDP */
  if (get_u_int32_t(packet->payload, 0) == 0x00000000)
  {
    isakmp_offset = 4;
    if (packet->payload_packet_len < 32)
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
  }

  if (packet->payload[isakmp_offset + 17] != 0x20 /* Major Version 2 */)
  {
    if (packet->payload[isakmp_offset + 17] != 0x10 /* Major Version 1 */)
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
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
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (isakmp_type == ISAKMP_V1)
  {
    isakmp_type = ndpi_int_check_isakmp_v1(packet, isakmp_offset, isakmp_type);
  } else {
    isakmp_type = ndpi_int_check_isakmp_v2(packet, isakmp_offset, isakmp_type);
  }

  ndpi_int_ipsec_add_connection(ndpi_struct, flow, isakmp_type);
}

void init_ipsec_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                          u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("IPSec", ndpi_struct, *id,
    NDPI_PROTOCOL_IPSEC,
    ndpi_search_ipsec,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );

  *id += 1;
}

