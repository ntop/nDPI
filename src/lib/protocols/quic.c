/*
 * quic.c
 *
 * Andrea Buscarinu - <andrea.buscarinu@gmail.com>
 * Michele Campus - <michelecampus5@gmail.com>
 * Copyright (C) 2012-15 - ntop.org
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include "ndpi_api.h"

#define SEQ_CID_MASK_ALL 0x3c // 0011 1100
#define QUIC_VER_MASK 0x01    // 0000 0001
#define CID_LEN_8 0x0C        // 0000 1100
#define CID_LEN_4 0x08        // 0000 1000
#define CID_LEN_1 0x04        // 0000 0100
#define CID_LEN_0 0x00        // 0000 0000
#define SEQ_MASK 0xf3         // 1111 0011
#define CID_MASK 0x0C         // 0000 1100


#ifdef NDPI_PROTOCOL_QUIC
static void ndpi_int_quic_add_connection(struct ndpi_detection_module_struct
                                         *ndpi_struct, struct ndpi_flow_struct *flow)
{
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_REAL_PROTOCOL);
}

void ndpi_search_quic(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    u_int16_t dport = 0, sport = 0;
    u_int ver_offs;
    u_int seq_offs;
    u_int cid_len;

     if(packet->udp != NULL) {
        sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
        NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "calculating quic over udp.\n");

        // Settings without version. First check if 0x00 PUBLIC FLAGS and SEQ != 0x00. SEQ must be 1 at least.
        if ((sport == 80 || dport == 80 || sport == 443 || dport == 443) && ((packet->payload[0] == 0x00 && packet->payload[1] != 0x00) ||
                                                                             (packet->payload[0] & SEQ_CID_MASK_ALL)))
        {
            // Filter packets with 1 byte SEQ.
            if (packet->payload[0] & SEQ_MASK == 0)
            {
                // Has no version, 1 byte SEQ.
                // Check CID length.
                switch (packet->payload[0] & CID_MASK)
                {
                   case CID_LEN_8: cid_len = 8; break;
                   case CID_LEN_4: cid_len = 4; break;
                   case CID_LEN_1: cid_len = 1; break;
                   case CID_LEN_0: cid_len = 0; break;
                   default:
                       NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude quic.\n");
                       NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
                }

                seq_offs = cid_len + 1;

                // SEQ must be 1 at least.
                if(packet->payload[seq_offs] == 0)
                {
                    NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude quic.\n");
                    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
                }
            }

            NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "found quic.\n");
            ndpi_int_quic_add_connection(ndpi_struct, flow);

        // Check if version, than the CID length.
        } else if (packet->payload[0] & QUIC_VER_MASK)
        {
            // Has version, check CID length.
            switch (packet->payload[0] & CID_MASK)
            {
               case CID_LEN_8: cid_len = 8; break;
               case CID_LEN_4: cid_len = 4; break;
               case CID_LEN_1: cid_len = 1; break;
               case CID_LEN_0: cid_len = 0; break;
               default:
                   NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude quic.\n");
                   NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
            }

            // Skip CID length.
            ver_offs = cid_len + 1 +1;
            unsigned char vers[] = {packet->payload[ver_offs], packet->payload[ver_offs + 1],
                                    packet->payload[ver_offs + 2], packet->payload[ver_offs + 3]};

                                     // Check version match.
                                     if (vers[0] == 'Q' && vers[1] == '0' &&
                                        (vers[2] == '2' && (vers[3] == '5' || vers[3] == '4' || vers[3] == '3' || vers[3] == '2' ||
                                                            vers[3] == '1' || vers[3] == '0')) ||
                                        (vers[2] == '1' && (vers[3] == '9' || vers[3] == '8' || vers[3] == '7' || vers[3] == '6' ||
                                                            vers[3] == '5' || vers[3] == '4' || vers[3] == '3' || vers[3] == '2' ||
                                                            vers[3] == '1' || vers[3] == '0')) ||
                                         (vers[2] == '0' && vers[3] == '9'))

                                     {
                                         NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "found quic.\n");
                                         ndpi_int_quic_add_connection(ndpi_struct, flow);
                                     }
            } else
            {
                NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude quic.\n");
                NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
            }
        }
     }
#endif
