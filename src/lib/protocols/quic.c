/*
 * quic.c
 *
 * Andrea Buscarinu - <andrea.buscarinu@gmail.com>
 * Michele Campus - <campus@ntop.org>
 *
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

#define QUIC_NO_V_RES_RSV 0xC3  // 1100 0011

#define QUIC_CID_MASK 0x0C      // 0000 1100
#define QUIC_VER_MASK 0x01      // 0000 0001
#define QUIC_SEQ_MASK 0x30      // 0011 0000

#define CID_LEN_8 0x0C          // 0000 1100
#define CID_LEN_0 0x00          // 0000 0000

#define CID_LEN_4 0x08          // 0000 1000
#define CID_LEN_1 0x04          // 0000 0100

#define SEQ_LEN_6 0x30          // 0011 0000
#define SEQ_LEN_4 0x20          // 0010 0000
#define SEQ_LEN_2 0x10          // 0001 0000
#define SEQ_LEN_1 0x00          // 0000 0000

#define INT(C) (C - '0')
#define DIGIT(X, Y, Z) ((isdigit(X) && isdigit(Y) && isdigit(Z)) ? (INT(X) * 100 + INT(Y) * 10 + INT(Z)) : 0)

#ifdef NDPI_PROTOCOL_QUIC
static void ndpi_int_quic_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_PROTOCOL_UNKNOWN);
}

static int connect_id(const unsigned char pflags)
{
    u_int cid_len;

    // Check CID length
    switch (pflags & QUIC_CID_MASK)
    {
    	case CID_LEN_8: cid_len = 8; break;
    	case CID_LEN_4: cid_len = 4; break;
    	case CID_LEN_1: cid_len = 1; break;
    	case CID_LEN_0: cid_len = 0; break;
    	default:
            return -1;
    }

    // Return offset
    return cid_len + 1;
}

static int sequence(const unsigned char *payload)
{
    char test[6] = {0};
    int cid_offs = connect_id(payload[0]);
    int seq_lens;

    // Retrieve SEQ offset.
    if (cid_offs >= 0)
    {
        // Search SEQ bytes length.
        switch (payload[0] & QUIC_SEQ_MASK)
        {
            case SEQ_LEN_6: seq_lens = 6; break;
            case SEQ_LEN_4: seq_lens = 4; break;
            case SEQ_LEN_2: seq_lens = 2; break;
            case SEQ_LEN_1: seq_lens = 1; break;
            default:
                return 0;
        }
    }

    // Return SEQ comp value;
    return memcmp(payload + cid_offs, test, seq_lens);
}

void ndpi_search_quic(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    int ver_offs;

    // UDP 2-bytes F/P
    if(packet->udp != NULL && packet->payload_packet_len > 2)
    {
    	u_int16_t sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);

    	NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "calculating QUIC over udp.\n");

        if (sport == 80 || dport == 80 || sport == 443 || dport == 443)
        {
            // Check if NO_VERS. PUBLIC FLAGS & SEQ/CID MASK == 0x0. SEQ must be -gt 0.
            if ((packet->payload[0] & QUIC_NO_V_RES_RSV) == 0 && sequence(packet->payload))
            {
                NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "found QUIC.\n");
                ndpi_int_quic_add_connection(ndpi_struct, flow);
            }

            // Version presence; CID length
            if (packet->payload[0] & QUIC_VER_MASK)
            {
                // Skip CID length
                ver_offs = connect_id(packet->payload[0]);

                if (ver_offs >= 0)
                {
                    const uint8_t *vers = &packet->payload[ver_offs];
                    short int res = DIGIT(vers[1], vers[2], vers[3]);

                    if (*vers == 'Q')
                    {
                        // QUIC versions. '22', '28' < omitted.
                        switch (res)
                        {
                            case 9:  case 10: case 11: case 12: case 13: case 14:
                            case 15: case 16: case 17: case 18: case 19: case 20:
                            case 21: case 23: case 24: case 25: case 26: case 27:
                            case 29: case 30: case 31: case 32: case 33: case 34:
                                NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "found QUIC.\n");
                                ndpi_int_quic_add_connection(ndpi_struct, flow);
                            break;
                            default:
                                NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude QUIC.\n");
                                NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
                        }
                    }
                }
            }
        }
        else
        {
            NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude QUIC.\n");
            NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
        }
    }
}

void init_quic_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
    ndpi_set_bitmask_protocol_detection("QUIC", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_QUIC, ndpi_search_quic,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

    *id += 1;
}

#endif
