/*
 * whatsapp.c
 *
 * Copyright (C) 2018 - ntop.org
 *
 * nDPI is free software: you can zmqtribute it and/or modify
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WHATSAPP

#include "ndpi_api.h"

#define WA_SEQ(seq) { .sequence_size = NDPI_ARRAY_LENGTH(seq) - 1 /* '\0' */, \
                      .sequence = seq }
#define GET_SEQ_SIZE(id) (whatsapp_sequences[id].sequence_size)
#define GET_SEQ(id) (whatsapp_sequences[id].sequence)

struct whatsapp_sequence {
  size_t const sequence_size;
  char const * const sequence;
};

enum whatsapp_sequence_id {
  WA_SEQ_NEW = 0,
  WA_SEQ_OLD,
  WA_SEQ_VERY_OLD,

  WA_SEQ_COUNT
};

static const struct whatsapp_sequence whatsapp_sequences[WA_SEQ_COUNT] = {
  WA_SEQ("\x45\x44\x00\x01\x00\x00\x04\x08"),
  WA_SEQ("\x45\x44\x00\x01\x00\x00\x02\x08"),
  WA_SEQ("\x57\x41\x01\x05")
};

static void ndpi_int_whatsapp_add_connection(struct ndpi_detection_module_struct * ndpi_struct,
                                             struct ndpi_flow_struct * flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found WhatsApp\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WHATSAPP,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static int ndpi_int_match_whatsapp_sequence(struct ndpi_detection_module_struct * ndpi_struct,
                                            struct ndpi_flow_struct * flow,
                                            enum whatsapp_sequence_id seq_id)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  if (flow->l4.tcp.wa_matched_so_far < GET_SEQ_SIZE(seq_id))
  {
    size_t match_len = GET_SEQ_SIZE(seq_id) - flow->l4.tcp.wa_matched_so_far;
    if (packet->payload_packet_len < match_len)
    {
      match_len = packet->payload_packet_len;
    }

    if (memcmp(packet->payload, &GET_SEQ(seq_id)[flow->l4.tcp.wa_matched_so_far],
               match_len) == 0)
    {
      flow->l4.tcp.wa_matched_so_far += match_len;
      if (flow->l4.tcp.wa_matched_so_far == GET_SEQ_SIZE(seq_id))
      {
        ndpi_int_whatsapp_add_connection(ndpi_struct, flow);
      }
      return 0;
    }
  }

  return 1;
}

static void ndpi_search_whatsapp(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search WhatsApp\n");

  if (flow->packet_counter > 3)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * This is a very old sequence (2015?) but we still have it in our unit tests.
   * Try to detect it, without too much effort...
   */
  if (flow->l4.tcp.wa_matched_so_far == 0 &&
      packet->payload_packet_len > GET_SEQ_SIZE(WA_SEQ_VERY_OLD) &&
      memcmp(packet->payload, GET_SEQ(WA_SEQ_VERY_OLD), GET_SEQ_SIZE(WA_SEQ_VERY_OLD)) == 0)
  {
    NDPI_LOG_INFO(ndpi_struct, "found WhatsApp (old sequence)\n");
    ndpi_int_whatsapp_add_connection(ndpi_struct, flow);
    return;
  }

  if (ndpi_int_match_whatsapp_sequence(ndpi_struct, flow, WA_SEQ_NEW) == 0 ||
      ndpi_int_match_whatsapp_sequence(ndpi_struct, flow, WA_SEQ_OLD) == 0)
  {
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_whatsapp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                             u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection(
    "WhatsApp", ndpi_struct, *id,
    NDPI_PROTOCOL_WHATSAPP,
    ndpi_search_whatsapp,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
	SAVE_DETECTION_BITMASK_AS_UNKNOWN,
	ADD_TO_DETECTION_BITMASK
  );
  *id += 1;
}
