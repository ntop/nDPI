/*
 * zoom.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ZOOM

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
  https://github.com/Princeton-Cabernet/zoom-analysis
  https://citizenlab.ca/2020/04/move-fast-roll-your-own-crypto-a-quick-look-at-the-confidentiality-of-zoom-meetings/
  https://github.com/marty90/rtc_pcap_cleaners
 */

PACK_ON struct zoom_sfu_enc { /* Zoom SFU encapsulation */
  u_int8_t  sfu_type; /* 3/4 = Zoom_0, 5 = RTCP/RTP */
  u_int16_t sequence_num;
  u_int32_t unknown;
  u_int8_t  direction; /* 0 = -> Zoom, 4 = <- Zoom */
} PACK_OFF;

PACK_ON struct zoom_media_enc { /* Zoom media encapsulation */
  u_int8_t  enc_type; /* 13/30 = Screen Share, 15 = Audio, 16 = Video, 33/34/35 = RTCP  */
  u_int32_t unknown_1, unknown_2;
  u_int16_t sequence_num;
  u_int32_t timestamp;
} PACK_OFF;

static int zoom_search_again(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow);

static void ndpi_int_zoom_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow,
					 u_int16_t master) {
  NDPI_LOG_INFO(ndpi_struct, "found Zoom\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZOOM, master, NDPI_CONFIDENCE_DPI);

  /* Keep looking for RTP if we are at the beginning of the flow (SFU 1 or 2).
   * It is similar to the STUN logic... */
  if(master == NDPI_PROTOCOL_UNKNOWN) {
    flow->max_extra_packets_to_check = 4;
    flow->extra_packets_func = zoom_search_again;
  }
}

static int is_zoom_port(struct ndpi_flow_struct *flow)
{
  /* https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0060548 */
  if((ntohs(flow->c_port) >= 8801 && ntohs(flow->c_port) <= 8810) ||
     (ntohs(flow->s_port) >= 8801 && ntohs(flow->s_port) <= 8810))
    return 1;
  return 0;
}

static int is_sfu_5(struct ndpi_detection_module_struct *ndpi_struct,
                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  /* SFU types 5 */
  if(packet->payload[0] == 0x05 &&
     packet->payload_packet_len > sizeof(struct zoom_sfu_enc) +
                                  sizeof(struct zoom_media_enc)) {
    struct zoom_media_enc *enc = (struct zoom_media_enc *)&packet->payload[sizeof(struct zoom_sfu_enc)];

    switch(enc->enc_type) {
    case 13: /* Screen Share */
    case 30: /* Screen Share */
      if(packet->payload_packet_len >= 27) {
        flow->flow_multimedia_type = ndpi_multimedia_screen_sharing_flow;
        return 1;
      }
      break;

    case 15: /* RTP Audio */
      if(packet->payload_packet_len >= 27) {
        flow->flow_multimedia_type = ndpi_multimedia_audio_flow;
        return 1;
      }
      break;

    case 16: /* RTP Video */
      if(packet->payload_packet_len >= 32) {
        flow->flow_multimedia_type = ndpi_multimedia_video_flow;
        return 1;
      }
      break;

    case 33: /* RTCP */
    case 34: /* RTCP */
    case 35: /* RTCP */
      if(packet->payload_packet_len >= 36) {
        return 1;
      }
      break;

    default:
      return 1;
    }
  }
  return 0;
}

static int zoom_search_again(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  if(is_sfu_5(ndpi_struct, flow)) {
    ndpi_int_zoom_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SRTP);
    return 0; /* Stop */
  }
  return 1; /* Keep looking */
}

static void ndpi_search_zoom(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t tomatch[] = { 0x01, 0x00, 0x03 };  /* Usually first pkt from the client */
  u_int8_t tomatch_a[] = { 0x01, 0x00, 0x02 };  /* Other first pkt from the client */
  u_int8_t tomatch2[] = { 0x02, 0x00, 0x03 }; /* Usually first pkt from the server: useful with asymmetric traffic */
  u_int8_t tomatch2_a[] = { 0x02, 0x00, 0x02 }; /* Other first pkt from the server */

  NDPI_LOG_DBG(ndpi_struct, "search Zoom\n");

  if(is_zoom_port(flow) &&
     packet->payload_packet_len > sizeof(struct zoom_sfu_enc)) {
    /* SFU types 1 and 2 */
    if(memcmp(packet->payload, tomatch, 3) == 0 ||
       memcmp(packet->payload, tomatch_a, 3) == 0 ||
       memcmp(packet->payload, tomatch2, 3) == 0 ||
       memcmp(packet->payload, tomatch2_a, 3) == 0) {
      ndpi_int_zoom_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN);
      return;

    /* SFU types 3 and 4. This check is quite weak but these packets are rare.
       Wait for other kind of traffic */
    } else if((packet->payload[0] == 0x03 || packet->payload[0] == 0x04) &&
              flow->packet_counter < 3) {
      return;

    /* SFU types 5 */
    } else if(is_sfu_5(ndpi_struct, flow)) {
      ndpi_int_zoom_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SRTP);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* *************************************************** */

void init_zoom_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("Zoom", ndpi_struct, *id,
				      NDPI_PROTOCOL_ZOOM,
				      ndpi_search_zoom,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
