/*
 * raknet.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RAKNET

#include "ndpi_api.h"

static void ndpi_int_raknet_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                           struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found RakNet\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_RAKNET,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static size_t raknet_dissect_ip(struct ndpi_packet_struct * const packet, size_t offset)
{
  if (offset + 1 >= packet->payload_packet_len ||
      (packet->payload[offset] != 0x04 /* IPv4 */ &&
       packet->payload[offset] != 0x06 /* IPv6 */))
  {
    return 0;
  }

  return (packet->payload[offset] == 0x04 ? 4 : 16);
}

/* Reference: https://wiki.vg/Raknet_Protocol */
void ndpi_search_raknet(struct ndpi_detection_module_struct *ndpi_struct,
                        struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  u_int8_t op, ip_addr_offset, required_packets = 3;

  NDPI_LOG_DBG(ndpi_struct, "search RakNet\n");

  if (packet->udp == NULL || packet->payload_packet_len < 7)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  op = packet->payload[0];

  switch (op)
  {
    case 0x00: /* Connected Ping */
      if (packet->payload_packet_len != 8)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }
      required_packets = 6;
      break;

    case 0x01: /* Unconnected Ping */
    case 0x02: /* Unconnected Ping */
      if (packet->payload_packet_len != 32)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }
      required_packets = 6;
      break;

    case 0x03: /* Connected Pong */
      if (packet->payload_packet_len != 16)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }
      required_packets = 6;
      break;

    case 0x05: /* Open Connection Request 1 */
      if (packet->payload_packet_len < 18 ||
          packet->payload[17] > 10 /* maximum supported protocol version */)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }
      required_packets = 6;
      break;

    case 0x06: /* Open Connection Reply 1 */
      if (packet->payload_packet_len != 28 ||
          packet->payload[25] > 0x01 /* connection uses encryption: bool -> 0x00 or 0x01 */)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }

      {
        u_int16_t mtu_size = ntohs(get_u_int16_t(packet->payload, 26));
        if (mtu_size > 1500 /* Max. supported MTU, see: http://www.jenkinssoftware.com/raknet/manual/programmingtips.html */)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
      }
      required_packets = 4;
      break;

    case 0x07: /* Open Connection Request 2 */
      ip_addr_offset = raknet_dissect_ip(packet, 17);
      if (packet->payload_packet_len != 34 || ip_addr_offset == 0)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }

      {
          u_int16_t mtu_size = ntohs(get_u_int16_t(packet->payload, 20 + ip_addr_offset));
          if (mtu_size > 1500 /* Max. supported MTU, see: http://www.jenkinssoftware.com/raknet/manual/programmingtips.html */)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }
      }
      break;

    case 0x08: /* Open Connection Reply 2 */
      ip_addr_offset = raknet_dissect_ip(packet, 25);
      if (packet->payload_packet_len != 35 || ip_addr_offset == 0)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }

      {
          u_int16_t mtu_size = ntohs(get_u_int16_t(packet->payload, 28 + ip_addr_offset));
          if (mtu_size > 1500 /* Max. supported MTU, see: http://www.jenkinssoftware.com/raknet/manual/programmingtips.html */)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }
      }
      break;

    case 0x10: /* Connection Request Accepted */
    case 0x13: /* New Incoming Connection */
      {
        ip_addr_offset = 4 + raknet_dissect_ip(packet, 0);
        if (op == 0x10)
        {
          ip_addr_offset += 2; // System Index
        }
        for (size_t i = 0; i < 10; ++i)
        {
          ip_addr_offset += 3 + raknet_dissect_ip(packet, ip_addr_offset);
        }
        ip_addr_offset += 16;
        if (ip_addr_offset != packet->payload_packet_len)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
      }
      break;

    /* Check for Frame Set Packet's */
    case 0x80:
    case 0x81:
    case 0x82:
    case 0x83:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
    case 0x88:
    case 0x89:
    case 0x8a:
    case 0x8b:
    case 0x8c:
    case 0x8d:
      {
        size_t frame_offset = 4;

        do {
          u_int8_t msg_flags = get_u_int8_t(packet->payload, frame_offset);
          if ((msg_flags & 0x0F) != 0)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }

          u_int16_t msg_size = ntohs(get_u_int16_t(packet->payload, frame_offset + 1));
          msg_size /= 8;
          if (msg_size == 0)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            break;
          }

          u_int8_t reliability_type = (msg_flags & 0xE0) >> 5;
          if (reliability_type >= 2 && reliability_type <= 4 /* is reliable? */)
          {
            frame_offset += 3;
          }
          if (reliability_type == 1 || reliability_type == 4 /* is sequenced? */)
          {
            frame_offset += 3;
          }
          if (reliability_type == 3 || reliability_type == 7 /* is ordered? */)
          {
            frame_offset += 4;
          }
          if ((msg_flags & 0x10) != 0 /* is fragmented? */)
          {
            frame_offset += 10;
          }

          frame_offset += msg_size + 3;
        } while (frame_offset + 3 <= packet->payload_packet_len);

        /* We've dissected enough to be sure. */
        if (frame_offset == packet->payload_packet_len)
        {
          ndpi_int_raknet_add_connection(ndpi_struct, flow);
        } else {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        }
        return;
      }
      break;

    case 0x09: /* Connection Request */
      if (packet->payload_packet_len != 16)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }
      required_packets = 6;
      break;

    case 0x15: /* Disconnect */
      required_packets = 8;
      break;

    case 0x19: /* Incompatible Protocol */
      if (packet->payload_packet_len != 25 ||
          packet->payload[17] > 10)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }
      break;

    case 0x1c: /* Unconnected Pong */
      if (packet->payload_packet_len < 35)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }

      {
        u_int16_t motd_len = ntohs(get_u_int16_t(packet->payload, 33));

        if (motd_len == 0 || motd_len + 35 != packet->payload_packet_len)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
      }
      break;

    case 0xa0: /* NACK */
    case 0xc0: /* ACK */
      {
        u_int16_t record_count = ntohs(get_u_int16_t(packet->payload, 1));
        size_t record_index = 0, record_offset = 3;

        do {
          if (packet->payload[record_offset] == 0x00 /* Range */)
          {
            record_offset += 7;
          } else if (packet->payload[record_offset] == 0x01 /* No Range */)
          {
            record_offset += 4;
          } else {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }
        } while (++record_index < record_count &&
                 record_offset + 4 <= packet->payload_packet_len);

        if (record_index == record_count && record_offset == packet->payload_packet_len)
        {
          ndpi_int_raknet_add_connection(ndpi_struct, flow);
        } else {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        }
        return;
      }
      break;

    case 0xfe: /* Game Packet */
      required_packets = 8;
      break;

    default: /* Invalid RakNet packet */
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
  }

  if (flow->packet_counter < required_packets)
  {
    return;
  }

  ndpi_int_raknet_add_connection(ndpi_struct, flow);
}

void init_raknet_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("RakNet", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_RAKNET,
				      ndpi_search_raknet,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
