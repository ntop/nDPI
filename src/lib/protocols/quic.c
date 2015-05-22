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

#define QUIC_NO_V_RES_RSV 0xC3

#define QUIC_CID_MASK 0x0C
#define QUIC_VER_MASK 0x01
#define QUIC_SEQ_MASK 0x30

#define CID_LEN_8 0x0C
#define CID_LEN_4 0x08
#define CID_LEN_1 0x04
#define CID_LEN_0 0x00

#define SEQ_LEN_6 0x30
#define SEQ_LEN_4 0x20
#define SEQ_LEN_2 0x10
#define SEQ_LEN_1 0x00

#define SEQ_CONV(ARR) (ARR[0] | ARR[1] | ARR[2] | ARR[3] | ARR[4] | ARR[5] << 8)


#ifdef NDPI_PROTOCOL_QUIC
static void ndpi_int_quic_add_connection(struct ndpi_detection_module_struct
                                         *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_REAL_PROTOCOL);
}

static int connect_id(const unsigned char pflags)
{
  u_int cid_len;

  switch (pflags & QUIC_CID_MASK)
    {
    case CID_LEN_8: cid_len = 8; break;
    case CID_LEN_4: cid_len = 4; break;
    case CID_LEN_1: cid_len = 1; break;
    case CID_LEN_0: cid_len = 0; break;
    default:
      return -1;

    }

  return cid_len + 1;
}

static int sequence(const unsigned char *payload)
{
  unsigned char conv[6] = {0};
  u_int seq_value = -1;
  int seq_lens;
  int cid_offs;
  int i;

  switch (payload[0] & QUIC_SEQ_MASK)
    {
    case SEQ_LEN_6: seq_lens = 6; break;
    case SEQ_LEN_4: seq_lens = 4; break;
    case SEQ_LEN_2: seq_lens = 2; break;
    case SEQ_LEN_1: seq_lens = 1; break;
    default:
      return -1;
    }

  cid_offs = connect_id(payload[0]);

  if (cid_offs != -1 && seq_lens > 0)
    {
      for (i = 0; i < seq_lens; i++)
	conv[i] = payload[cid_offs + i];

      seq_value = SEQ_CONV(conv);
    }

  return seq_value;
}

void ndpi_search_quic(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  unsigned char *vers;
  int ver_offs;

  if(packet->udp != NULL)
    {
      u_int16_t sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);

      NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "calculating quic over udp.\n");

      if(((packet->payload[0] & 0xC2) != 0) || (!(sport == 80 || dport == 80 || sport == 443 || dport == 443)))
	goto exclude_quic;

      /* Quic without version. First check if PUBLIC FLAGS & SEQ bytes are 0x0, SEQ must be greater than zero */
      if (((packet->payload[0] == 0x00) && (packet->payload[1] != 0x00)) || ((packet->payload[0] & QUIC_NO_V_RES_RSV) == 0))
        {
	  if (sequence(packet->payload) < 1)
            {
	      NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude quic.\n");
	      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
            }

	  NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "found quic.\n");
	  ndpi_int_quic_add_connection(ndpi_struct, flow);
        }

      else if (packet->payload[0] & QUIC_VER_MASK)
        {
	  ver_offs = connect_id(packet->payload[0]);

	  if (ver_offs != -1){
	    vers = (unsigned char*)(packet->payload + ver_offs);

	    if ((vers[0] == 'Q' && vers[1] == '0') &&
		((vers[2] == '2' && (vers[3] == '5' || vers[3] == '4' || vers[3] == '3' || vers[3] == '2' ||
				     vers[3] == '1' || vers[3] == '0')) ||
		 (vers[2] == '1' && (vers[3] == '9' || vers[3] == '8' || vers[3] == '7' || vers[3] == '6' ||
				     vers[3] == '5' || vers[3] == '4' || vers[3] == '3' || vers[3] == '2' ||
				     vers[3] == '1' || vers[3] == '0')) ||
		 (vers[2] == '0' && vers[3] == '9')))

	      {
		NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "found quic.\n");
		ndpi_int_quic_add_connection(ndpi_struct, flow);
	      }
	  }
        } else
        {
        exclude_quic:
	  NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude quic.\n");
	  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
        }
    }
}
#endif
