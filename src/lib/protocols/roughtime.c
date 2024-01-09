/*
 * roughtime.c
 *
 * Copyright (C) 2024 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ROUGHTIME

#include "ndpi_api.h"
#include "ndpi_private.h"

static u_int32_t const valid_tags[] = {
  0x00444150 /* PAD */,
  0x00474953 /* SIG */,
  0x00524556 /* VER */,
  0x31545544 /* DUT1 */,
  0x434e4f4e /* NONC */,
  0x454c4544 /* DELE */,
  0x48544150 /* PATH */,
  0x49415444 /* DTAI */,
  0x49444152 /* RADI */,
  0x4b425550 /* PUBK */,
  0x5041454c /* LEAP */,
  0x5044494d /* MIDP */,
  0x50455253 /* SREP */,
  0x544e494d /* MINT */,
  0x544f4f52 /* ROOT */,
  0x54524543 /* CERT */,
  0x5458414d /* MAXT */,
  0x58444e49 /* INDX */,
  /*
   * It seems that some implementations are not following the specs
   * by using 0xFF instead of 0x00 as ASCII NUL.
   */
  0xFF444150 /* PAD */,
  0xFF474953 /* SIG */,
  0xFF524556 /* VER */,
  /*
   * Newer drafts may have the following additional tag.
   */
  0x7a7a7a7a /* ZZZZ */,
};

static void ndpi_int_roughtime_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                              struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found roughtime\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_ROUGHTIME,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_roughtime(struct ndpi_detection_module_struct *ndpi_struct,
                                  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_INFO(ndpi_struct, "search roughtime\n");

  if (packet->payload_packet_len < 4)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  u_int32_t number_of_tags = le32toh(get_u_int32_t(packet->payload, 0));
  size_t const minimum_length = 4 /* number of tags (N) */ +
                               (number_of_tags - 1) * 4 /* number of tag offsets (N-1) */ +
                               (number_of_tags * 4) /* tags itself (N) */;
  if (number_of_tags < 1 || packet->payload_packet_len < minimum_length ||
      number_of_tags > NDPI_ARRAY_LENGTH(valid_tags))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (number_of_tags > 1) {
    u_int32_t tag_offset = le32toh(get_u_int32_t(packet->payload, 4 + (number_of_tags - 2) * 4));
    if (packet->payload_packet_len < 4 + (number_of_tags - 1) * 4 + tag_offset)
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
  }

  size_t i;
  for (i = 0; i < number_of_tags; ++i)
  {
    u_int32_t tag = le32toh(get_u_int32_t(packet->payload, 4 + (number_of_tags - 1) * 4 + i * 4));

    size_t j;
    for (j = 0; j < NDPI_ARRAY_LENGTH(valid_tags); ++j)
    {
      if (tag == valid_tags[j])
      {
        break;
      }
    }
    if (j == NDPI_ARRAY_LENGTH(valid_tags))
    {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
  }

  ndpi_int_roughtime_add_connection(ndpi_struct, flow);
}

void init_roughtime_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                              u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Roughtime", ndpi_struct, *id,
    NDPI_PROTOCOL_ROUGHTIME,
    ndpi_search_roughtime,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );

  *id += 1;
}
