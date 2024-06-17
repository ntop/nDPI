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
static int keep_extra_dissection(struct ndpi_flow_struct *flow);

static void ndpi_int_zoom_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow) {
  u_int16_t master;

  if(flow->flow_multimedia_type != ndpi_multimedia_unknown_flow)
    master = NDPI_PROTOCOL_SRTP;
  else
    master = NDPI_PROTOCOL_UNKNOWN;

  NDPI_LOG_INFO(ndpi_struct, "found Zoom\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZOOM, master, NDPI_CONFIDENCE_DPI);

  if(!flow->extra_packets_func) {
    if(keep_extra_dissection(flow) &&
       ndpi_struct->cfg.zoom_max_packets_extra_dissection > 0) {
      NDPI_LOG_DBG(ndpi_struct, "Enabling extra dissection\n");
      flow->max_extra_packets_to_check = ndpi_struct->cfg.zoom_max_packets_extra_dissection;
      flow->extra_packets_func = zoom_search_again;
    }
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

static int is_zme(struct ndpi_detection_module_struct *ndpi_struct,
                  struct ndpi_flow_struct *flow,
                  const u_char *payload, u_int16_t payload_len)
{
  if(payload_len > sizeof(struct zoom_media_enc)) {
    struct zoom_media_enc *enc = (struct zoom_media_enc *)payload;

    switch(enc->enc_type) {
    case 13: /* Screen Share: RTP is not always there, expecially at the beginning of the flow */
      if(payload_len > 27) {
         if(is_rtp_or_rtcp(ndpi_struct, payload + 27, payload_len - 27, NULL) == IS_RTP) {
           flow->flow_multimedia_type = ndpi_multimedia_screen_sharing_flow;
         }
         return 1;
      }
      break;

    case 30: /* P2P Screen Share: it seems RTP is always present */
      if(payload_len > 20 &&
         is_rtp_or_rtcp(ndpi_struct, payload + 20, payload_len - 20, NULL) == IS_RTP) {
        flow->flow_multimedia_type = ndpi_multimedia_screen_sharing_flow;
        return 1;
      }
      break;

    case 15: /* RTP Audio */
      if(payload_len > 19 &&
         is_rtp_or_rtcp(ndpi_struct, payload + 19, payload_len - 19, NULL) == IS_RTP) {
        flow->flow_multimedia_type = ndpi_multimedia_audio_flow;
        return 1;
      }
      break;

    case 16: /* RTP Video */
      if(payload_len > 24 &&
         is_rtp_or_rtcp(ndpi_struct, payload + 24, payload_len - 24, NULL) == IS_RTP) {
        flow->flow_multimedia_type = ndpi_multimedia_video_flow;
        return 1;
      }
      break;

    case 33: /* RTCP */
    case 34: /* RTCP */
    case 35: /* RTCP */
      if(payload_len > 16 &&
         is_rtp_or_rtcp(ndpi_struct, payload + 16, payload_len - 16, NULL) == IS_RTCP) {
        return 1;
      }
      break;

    default:
      return 0;
    }
  }
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
    return is_zme(ndpi_struct, flow, &packet->payload[sizeof(struct zoom_sfu_enc)],
                  packet->payload_packet_len - sizeof(struct zoom_sfu_enc));
  }
  return 0;
}

static int keep_extra_dissection(struct ndpi_flow_struct *flow)
{
  return flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN; /* No sub-classification */
}

static int zoom_search_again(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(!flow->l4.udp.zoom_p2p &&
     is_sfu_5(ndpi_struct, flow)) {
    ndpi_int_zoom_add_connection(ndpi_struct, flow);
  }
  if(flow->l4.udp.zoom_p2p &&
     is_zme(ndpi_struct, flow, packet->payload, packet->payload_packet_len)) {
    ndpi_int_zoom_add_connection(ndpi_struct, flow);
  }

  return keep_extra_dissection(flow);
}

static void ndpi_search_zoom(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t tomatch[] = { 0x01, 0x00, 0x03 };  /* Usually first pkt from the client */
  u_int8_t tomatch_a[] = { 0x01, 0x00, 0x02 };  /* Other first pkt from the client */
  u_int8_t tomatch2[] = { 0x02, 0x00, 0x03 }; /* Usually first pkt from the server: useful with asymmetric traffic */
  u_int8_t tomatch2_a[] = { 0x02, 0x00, 0x02 }; /* Other first pkt from the server */
  u_int8_t tomatch_p2p[] = { 0x1f, 0x02, 0x01 }; /* Usually first pkt for P2P connections */

  NDPI_LOG_DBG(ndpi_struct, "search Zoom\n");

  if(is_zoom_port(flow) &&
     packet->payload_packet_len > sizeof(struct zoom_sfu_enc)) {
    /* SFU types 1 and 2 */
    if(memcmp(packet->payload, tomatch, 3) == 0 ||
       memcmp(packet->payload, tomatch_a, 3) == 0 ||
       memcmp(packet->payload, tomatch2, 3) == 0 ||
       memcmp(packet->payload, tomatch2_a, 3) == 0) {
      ndpi_int_zoom_add_connection(ndpi_struct, flow);
      return;

    /* SFU types 3 and 4. This check is quite weak: let give time to the other
       dissectors to kick in */
    } else if((packet->payload[0] == 0x03 || packet->payload[0] == 0x04)) {
      if(flow->packet_counter < 4)
        return;
      ndpi_int_zoom_add_connection(ndpi_struct, flow);
      return;

    /* SFU types 5 */
    } else if(is_sfu_5(ndpi_struct, flow)) {
      ndpi_int_zoom_add_connection(ndpi_struct, flow);
      return;
    }
  } else if(packet->payload_packet_len > 36 &&
            memcmp(packet->payload, tomatch_p2p, 3) == 0 &&
            *(u_int32_t *)&packet->payload[packet->payload_packet_len - 4] == 0) {
    u_int64_t ip_len, uuid_len;

    /* Check if it is a Peer-To-Peer call.
       According to the paper, P2P calls should use "Zoom Media Encapsulation"
       header without any "Zoom SFU Encapsulation".
       Looking at the traces, it seems that the packet structure is something like:
       * ZME type 0x1F
       * initial header 24 byte long, without any obvious sequence number field
       * a Length-Value list of attributes (4 bytes length field)
         * an ip address (as string)
         * some kind of UUID
       * 4 bytes as 0x00 at the end
    */

    ip_len = ntohl(*(u_int32_t *)&packet->payload[24]);

    if(24 + 4 + ip_len + 4 < packet->payload_packet_len) {
      uuid_len = ntohl(*(u_int32_t *)&packet->payload[24 + 4 + ip_len]);

      if(packet->payload_packet_len == 24 + 4 + ip_len + 4 + uuid_len + 4) {
        NDPI_LOG_DBG(ndpi_struct, "found P2P Zoom\n");
        flow->l4.udp.zoom_p2p = 1;
        ndpi_int_zoom_add_connection(ndpi_struct, flow);
        return;
      }
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
