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

#define QUIC_NO_V_RES_RSV 0xf3  // 1100 0011

#define QUIC_CID_MASK 0x0C      // 0000 1100
#define QUIC_VER_MASK 0x01      // 0000 0001
#define QUIC_SEQ_MASK 0x30      // 0011 0000

#define CID_LEN_8 0x0C          // 0000 1100
#define CID_LEN_4 0x08          // 0000 1000
#define CID_LEN_1 0x04          // 0000 0100
#define CID_LEN_0 0x00          // 0000 0000

#define SEQ_LEN_6 0x30          // 0011 0000
#define SEQ_LEN_4 0x20          // 0010 0000
#define SEQ_LEN_2 0x10          // 0001 0000
#define SEQ_LEN_1 0x00          // 0000 0000

#define SEQ_CONV_6(ARR) (ARR[0] | ARR[1] | ARR[2] | ARR[3] | ARR[4] | ARR[5] << 8)
#define SEQ_CONV_4(ARR) (ARR[0] | ARR[1] | ARR[2] | ARR[3] << 8)
#define SEQ_CONV_2(ARR) (ARR[0] | ARR[1] << 8)
#define SEQ_CONV_1(ARR) (ARR[0] << 8)


#ifdef NDPI_PROTOCOL_QUIC
static void ndpi_int_quic_add_connection(struct ndpi_detection_module_struct
                                         *ndpi_struct, struct ndpi_flow_struct *flow)
{
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_REAL_PROTOCOL);
}

int connect_id(const unsigned char pflags)
{
    u_int cid_len;

        // Check CID length.
        switch (pflags & QUIC_CID_MASK)
        {
           case CID_LEN_8: cid_len = 8; break;
           case CID_LEN_4: cid_len = 4; break;
           case CID_LEN_1: cid_len = 1; break;
           case CID_LEN_0: cid_len = 0; break;
           default:
               return -1;

        }
        // Return offset.
        return cid_len + 1;
}

int sequence(const unsigned char *payload)
{
    unsigned char* conv;
    u_int seq_len;
    u_int cid_offs;
    u_int seq_value;
    int i;

        switch (payload[0] & QUIC_SEQ_MASK)
        {
           case SEQ_LEN_6: seq_len = 6; break;
           case SEQ_LEN_4: seq_len = 4; break;
           case SEQ_LEN_2: seq_len = 2; break;
           case SEQ_LEN_1: seq_len = 1; break;
           default:
               return -1;
        }

        if (seq_len > 0) calloc(seq_len, sizeof(unsigned char));
        cid_offs = connect_id(payload[0]);

        if (cid_offs >= 0)
        {
            for (i = cid_offs; i < seq_len; i++)
                conv[i] = payload[i];

            switch (seq_len)
            {
               case 6: seq_value = SEQ_CONV_6(conv); break;
               case 4: seq_value = SEQ_CONV_4(conv); break;
               case 2: seq_value = SEQ_CONV_2(conv); break;
               case 1: seq_value = SEQ_CONV_1(conv); break;
               default:
                   return -1;
            }
            // Return SEQ int value;
            return seq_value;
        }
}

void ndpi_search_quic(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    u_int16_t dport = 0, sport = 0;
    u_int ver_offs;

    if(packet->udp != NULL) {
        sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
        NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "calculating quic over udp.\n");

        // Settings without version. First check if PUBLIC FLAGS & SEQ bytes are 0x0. SEQ must be 1 at least.
        if ((sport == 80 || dport == 80 || sport == 443 || dport == 443) && ((packet->payload[0] == 0x00 && packet->payload[1] != 0x00) ||
                                                                             (packet->payload[0] & (QUIC_NO_V_RES_RSV) == 0)))
        {
            if (sequence(packet->payload) < 1)
            {

                NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude quic.\n");
                NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
            }

            NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "found quic.\n");
            ndpi_int_quic_add_connection(ndpi_struct, flow);
        }

        // Check if version, than the CID length.
        else if (packet->payload[0] & QUIC_VER_MASK)
        {
            // Skip CID length.
            ver_offs = connect_id(packet->payload[0]);

            if (ver_offs >= 0){
                unsigned char vers[] = {packet->payload[ver_offs], packet->payload[ver_offs + 1],
                                        packet->payload[ver_offs + 2], packet->payload[ver_offs + 3]};

                // Version Match.
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
            }
        } else
        {
            NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude quic.\n");
            NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
        }
    }
}
#endif
