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

#define QUIC_NO_V_RES_RSV 0xC3 // 1100 0001

#define QUIC_FLG_VERS 0x01     // 0000 0001
#define QUIC_FLG_RSET 0x02     // 0000 0010
#define QUIC_FLG_NNCE 0x04     // 0000 0100
#define QUIC_FLG_CIDL 0x08     // 0000 1000
#define QUIC_FLG_PACK 0x30     // 0011 0000
#define QUIC_FLG_PATH 0x40     // 0100 0000

#define OFF_LEN_00 0x00        // 0000 0000
#define OFF_LEN_04 0x04        // 0000 0100
#define OFF_LEN_08 0x08        // 0000 1000
#define OFF_LEN_0C 0x0C        // 0000 1100

#define PKN_LEN_1 0x00         // 0000 0000
#define PKN_LEN_2 0x10         // 0001 0000
#define PKN_LEN_4 0x20         // 0010 0000
#define PKN_LEN_6 0x30         // 0011 0000


#define INT(C) (C - '0')
#define DIGIT(X, Y, Z) ((isdigit(X) && isdigit(Y) && isdigit(Z)) ? (INT(X) * 100 + INT(Y) * 10 + INT(Z)) : 0)

#ifdef NDPI_PROTOCOL_QUIC
static void ndpi_int_quic_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_PROTOCOL_UNKNOWN);
}

static int ports(u_int16_t sport, u_int16_t dport)
{
    if ((sport == 443 || dport == 443 || sport == 80 || dport == 80) &&
        (sport != 123 && dport != 123))
        return 0;
    return 1;
}

static int offset(const unsigned char pflags)
{
    u_int offs;

    switch (pflags & (QUIC_FLG_CIDL | QUIC_FLG_NNCE))
    {
    	case OFF_LEN_08: offs = 8; break;
    	case OFF_LEN_0C: offs = 8; break;
    	default:
            return 1;
    }
    return offs + 1;
}

static int vers(const unsigned char *payload)
{
    int voffs = offset(*payload);
    const uint8_t *vers = &payload[voffs];

    if (*vers == 'Q')
    {
        short int res = DIGIT(vers[1], vers[2], vers[3]);

        switch (res)
        {
            case 9:  case 10: case 11: case 12: case 13: case 14:
            case 15: case 16: case 17: case 18: case 19: case 20:
            case 21: case 23: case 24: case 25: case 26: case 27:
            case 29: case 30: case 31: case 32: case 33: case 34:
                return 0;
                break;
            default:
                return 1;
        }
    }
    return 1;
}

void ndpi_search_quic(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    u_int32_t udp_len = packet->payload_packet_len;

    if (packet->udp != NULL && udp_len > 2)
    {
    	u_int16_t sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);

    	NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "calculating QUIC over udp.\n");

        if ((ports(sport, dport) == 0 && (packet->payload[0] & QUIC_NO_V_RES_RSV) == 0)
            || vers(packet->payload) == 0)
        {
            NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "found QUIC.\n");
            ndpi_int_quic_add_connection(ndpi_struct, flow);
        }
        else
        {
            NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude QUIC.\n");
            NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
        }
    }
    else
    {
        NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude QUIC.\n");
        NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
    }
}

void init_quic_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
    ndpi_set_bitmask_protocol_detection("QUIC", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_QUIC, ndpi_search_quic,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

    *id += 1;
}

#endif
