/*
 * rtp.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-25 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RTP

#include "ndpi_api.h"
#include "ndpi_private.h"

#define RTP_MIN_HEADER	12
#define RTCP_MIN_HEADER	8

static void ndpi_rtp_search(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow);

/* *************************************************************** */

/* https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml */
int is_valid_rtp_payload_type(uint8_t type)
{
  if(!(type <= 34 || (type >= 96 && type <= 127)))
    return 0;
  return 1;
}

/* *************************************************************** */

u_int8_t rtp_get_stream_type(u_int8_t payloadType, u_int8_t *s_type, u_int16_t sub_proto)
{
  /* General, from IANA */
  switch(payloadType) {
  case 0: /* G.711 u-Law */
  case 3: /* GSM 6.10 */
  case 4: /* G.723.1  */
  case 5: /* DVI4 */
  case 6: /* DVI4 */
  case 7: /* LPC */
  case 8: /* G.711 A-Law */
  case 9: /* G.722 */
  case 10: /* L16 */
  case 11: /* L16 */
  case 12: /* QCELP */
  case 13: /* Comfort Noise */
  case 14: /* MPA */
  case 15: /* G728 */
  case 16: /* DVI4 */
  case 17: /* DVI4 */
  case 18: /* G729 */
    *s_type |= ndpi_multimedia_audio_flow;
    return(1);

  case 25: /* CelB */
  case 26: /* JPEG */
  case 28: /* nv */
  case 31: /* H261 */
  case 32: /* MPV */
  case 34: /* H263 */
    *s_type |= ndpi_multimedia_video_flow;
    return(1);
  }

  /* Microsoft; from https://learn.microsoft.com/en-us/openspecs/office_protocols/ms-rtp/3b8dc3c6-34b8-4827-9b38-3b00154f471c */
  if(sub_proto == NDPI_PROTOCOL_MSTEAMS_CALL) {
    switch(payloadType) {
    case 103: /* SILK Narrowband */
    case 104: /* SILK Wideband */
    case 106: /* OPUS */
    case 111: /* Siren */
    case 112: /* G.722.1 */
    case 114: /* RT Audio Wideband */
    case 115: /* RT Audio Narrowband */
    case 116: /* G.726 */
    case 117: /* G.722 */
    case 118: /* Comfort Noise Wideband */
      *s_type |= ndpi_multimedia_audio_flow;
      return(1);

    case 34: /* H.263 [MS-H26XPF] */
    case 121: /* RT Video */
    case 122: /* H.264 [MS-H264PF] */
    case 123: /* H.264 FEC [MS-H264PF] */
      *s_type |= ndpi_multimedia_video_flow;
      return(1);

    default:
      *s_type |= ndpi_multimedia_unknown_flow;
      return(0);
    }
  }

  /* Dynamic PTs are... dynamic... :D
   * Looking at some traces, it seems specific applications keep using
   * always the same PT for audio/video...
   * TODO: something better?
   * Bottom line: checking only PT is very fast/easy, but we might have
   * false positives/negatives
   */

  if(sub_proto == NDPI_PROTOCOL_GOOGLE_CALL) {
    switch(payloadType) {
    case 111:
      *s_type |= ndpi_multimedia_audio_flow;
      return(1);

    case 96:
    case 100:
      *s_type |= ndpi_multimedia_video_flow;
      return(1);

    default:
      *s_type |= ndpi_multimedia_unknown_flow;
      return(0);
    }
  }

  if(sub_proto == NDPI_PROTOCOL_WHATSAPP_CALL) {
    switch(payloadType) {
    case 120:
      *s_type |= ndpi_multimedia_audio_flow;
      return(1);

    case 97:
    case 102:
      *s_type |= ndpi_multimedia_video_flow;
      return(1);

    default:
      *s_type |= ndpi_multimedia_unknown_flow;
      return(0);
    }
  }

  if(sub_proto == NDPI_PROTOCOL_FACEBOOK_VOIP) {
    switch(payloadType) {
    case 96:
    case 97:
    case 101:
    case 109:
      *s_type |= ndpi_multimedia_audio_flow;
      return(1);

    case 127:
      *s_type |= ndpi_multimedia_video_flow;
      return(1);

    default:
      *s_type |= ndpi_multimedia_unknown_flow;
      return(0);
    }
  }

  if(sub_proto == NDPI_PROTOCOL_TELEGRAM_VOIP) {
    switch(payloadType) {
    case 111:
      *s_type |= ndpi_multimedia_audio_flow;
      return(1);

    case 106:
      *s_type |= ndpi_multimedia_video_flow;
      return(1);

    default:
      *s_type |= ndpi_multimedia_unknown_flow;
      return(0);
    }
  }

  if(sub_proto == NDPI_PROTOCOL_SIGNAL_VOIP) {
    switch(payloadType) {
    case 102:
      *s_type |= ndpi_multimedia_audio_flow;
      return(1);

    case 108:
    case 120:
      *s_type |= ndpi_multimedia_video_flow;
      return(1);

    default:
      *s_type |= ndpi_multimedia_unknown_flow;
      return(0);
    }
  }

  *s_type |= ndpi_multimedia_unknown_flow;
  return(0);
}

/* *************************************************************** */

static int is_valid_rtcp_payload_type(uint8_t type) {
  return (type >= 192 && type <= 213);
}

/* *************************************************************** */

int is_rtp_or_rtcp(struct ndpi_detection_module_struct *ndpi_struct,
                   const u_int8_t *payload, u_int16_t payload_len, u_int16_t *seq)
{
  u_int8_t csrc_count, ext_header;
  u_int16_t ext_len;
  u_int32_t min_len;

  if(payload_len < 2)
    return NO_RTP_RTCP;

  if((payload[0] & 0xC0) != 0x80) { /* Version 2 */
    NDPI_LOG_DBG(ndpi_struct, "Not version 2\n");
    return NO_RTP_RTCP;
  }

  if(is_valid_rtp_payload_type(payload[1] & 0x7F) &&
     payload_len >= RTP_MIN_HEADER) {
    /* RTP */
    csrc_count = payload[0] & 0x0F;
    ext_header =  !!(payload[0] & 0x10);
    min_len = RTP_MIN_HEADER + 4 * csrc_count + 4 * ext_header;
    if(ext_header) {
      if(min_len > payload_len) {
        NDPI_LOG_DBG(ndpi_struct, "Too short (a) %d vs %d\n", min_len, payload_len);
        return NO_RTP_RTCP;
      }
      ext_len = ntohs(*(unsigned short *)&payload[min_len - 2]);
      min_len += ext_len * 4;
    }
    if(min_len > payload_len) {
      NDPI_LOG_DBG(ndpi_struct, "Too short (b) %d vs %d\n", min_len, payload_len);
      return NO_RTP_RTCP;
    }
    /* Check on padding doesn't work because:
     * we may have multiple RTP packets in the same TCP/UDP datagram
     * with SRTP, padding_length field is encrypted */
    if(seq)
      *seq = ntohs(*(unsigned short *)&payload[2]);
    return IS_RTP;
  } else if(is_valid_rtcp_payload_type(payload[1]) &&
            payload_len >= RTCP_MIN_HEADER) {
    min_len = (ntohs(*(unsigned short *)&payload[2]) + 1) * 4;
    if(min_len > payload_len) {
      NDPI_LOG_DBG(ndpi_struct, "Too short (c) %d vs %d\n", min_len, payload_len);
      return NO_RTP_RTCP;
    }
    return IS_RTCP;
  }
  NDPI_LOG_DBG(ndpi_struct, "not RTP/RTCP\n");
  return NO_RTP_RTCP;
}

/* ************************************************************ */

static int rtp_search_again(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow) {
  /* printf("***** AGAIN *****\n"); */
  ndpi_rtp_search(ndpi_struct, flow);

  return(((flow->rtp[0].payload_detected && flow->rtp[1].payload_detected)) ? false :true);
}

/* *************************************************************** */

static void ndpi_int_rtp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                        struct ndpi_flow_struct *flow,
                                        u_int16_t proto)
{
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_UNKNOWN, proto,
                             NDPI_CONFIDENCE_DPI);
  if(ndpi_struct->cfg.rtp_search_for_stun) {
    /* It makes sense to look for STUN only if we didn't capture the entire flow,
       from the beginning */
    if(!(flow->l4_proto == IPPROTO_TCP && ndpi_seen_flow_beginning(flow))) {
      NDPI_LOG_DBG(ndpi_struct, "Enabling (STUN) extra dissection\n");
      switch_extra_dissection_to_stun(ndpi_struct, flow, 1);
    }
  } else if(proto == NDPI_PROTOCOL_RTP) {
    if(flow->rtp[0].payload_detected && flow->rtp[1].payload_detected)
      ; /* Nothing to do */
    else {
      if(!flow->extra_packets_func) {
	NDPI_LOG_DBG(ndpi_struct, "Enabling extra dissection\n");
	flow->max_extra_packets_to_check = ndpi_struct->cfg.rtp_max_packets_extra_dissection;
	flow->extra_packets_func = rtp_search_again;
      }
    }
  }
}

/* *************************************************************** */

static void ndpi_rtp_search(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow) {
  u_int8_t is_rtp;
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *payload = packet->payload;
  u_int16_t payload_len = packet->payload_packet_len;
  u_int16_t seq;

  if(payload_len == 0) return;
  
  if(packet->tcp != NULL) {
    if (payload_len < 2) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      NDPI_EXCLUDE_PROTO_EXT(ndpi_struct, flow, NDPI_PROTOCOL_RTCP);
      return;
    }
    payload += 2; /* Skip the length field */
    payload_len -= 2;
  }
  NDPI_LOG_DBG(ndpi_struct, "search RTP (stage %d/%d)\n", flow->rtp_stage, flow->rtcp_stage);

  /* * Let some "unknown" packets at the beginning:
   * search for 3/4 consecutive RTP/RTCP packets.
   * Wait a little longer (4 vs 3 pkts) for RTCP to try to tell if there are only
   * RTCP packets in the flow or if RTP/RTCP are multiplexed together */

  if(flow->packet_counter > 3 &&
     flow->rtp_stage == 0 &&
     flow->rtcp_stage == 0) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    NDPI_EXCLUDE_PROTO_EXT(ndpi_struct, flow, NDPI_PROTOCOL_RTCP);
    return;
  }

  is_rtp = is_rtp_or_rtcp(ndpi_struct, payload, payload_len, &seq);

  if(is_rtp == IS_RTP) {
    u_int8_t packet_direction = current_pkt_from_client_to_server(ndpi_struct, flow) ? 0 : 1;
    
    if(flow->rtp[packet_direction].payload_type == 0x0) {
      flow->rtp[packet_direction].payload_type = payload[1] & 0x7F;
      flow->rtp[packet_direction].payload_detected = true;
      
      /* printf("********* [direction: %d] payload_type=%u\n", packet_direction, flow->protos.rtp[packet_direction].payload_type);  */
      
      if(((flow->rtp[packet_direction].payload_type == 126 /* Enhanced Voice Services (EVS) */)
	  || (flow->rtp[packet_direction].payload_type == 127 /* Enhanced Voice Services (EVS) */))
	 && (payload_len > 12 /* RTP header */)) {
	const u_int8_t *evs = &payload[12];
	u_int packet_len = payload_len - 12;
	u_int num_bits = packet_len * 8;

	flow->flow_multimedia_types = ndpi_multimedia_audio_flow;
	/* printf("********* %02X [bits %u]\n", evs[0], num_bits); */
	  
	if(num_bits == 56) {
	  /* A.2.1.3 Special case for 56 bit payload size (EVS Primary or EVS AMR-WB IO SID) */

	  if((evs[0] & 0x80) == 0)
	    flow->rtp[packet_direction].evs_subtype = evs[0] & 0xF;
	  else
	    flow->rtp[packet_direction].evs_subtype = evs[1] & 0xF;
	} else {

	  /* See ndpi_rtp_payload_type2str() */
	  switch(num_bits) {
	  case    48:
	  case   136:
	  case   144:
	  case   160:
	  case   184:
	  case   192:
	  case   256:
	  case   264:
	  case   288:
	  case   320:
	  case   328:
	  case   368:
	  case   400:
	  case   464:
	  case   480:
	  case   488:
	  case   640:
	  case   960:
	  case  1280:
	  case  1920:
	  case  2560:
	    flow->rtp[packet_direction].evs_subtype = num_bits;
	    break;

	  default:
	    if((evs[0] >> 7) == 1) {
	      /* EVS Codec Mode Request (EVS-CMR) */
	      u_int8_t d_bits = evs[0] & 0X0F;
	      
	      flow->rtp[packet_direction].evs_subtype = d_bits + 30 /* dummy offset */;
	    }
	    break;
	  }
	}	

	if(flow->rtp[0].payload_detected && flow->rtp[1].payload_detected)
	  flow->extra_packets_func = NULL; /* Nothing to do */	 
      }
    }

    if(flow->rtp_stage == 2) {
      if(flow->l4_proto == IPPROTO_UDP &&
         flow->l4.udp.line_pkts[0] >= 2 && flow->l4.udp.line_pkts[1] >= 2) {
        /* It seems that it is a LINE stuff; let its dissector to evaluate */
      } else if(flow->l4_proto == IPPROTO_UDP && flow->l4.udp.epicgames_stage > 0) {
        /* It seems that it is a EpicGames stuff; let its dissector to evaluate */
      } else if(flow->rtp_seq_set[packet->packet_direction] &&
                flow->rtp_seq[packet->packet_direction] == seq) {
        /* Simple heuristic to avoid false positives. tradeoff between:
	 * consecutive RTP packets should have different sequence number
	 * we should handle duplicated traffic */
        NDPI_LOG_DBG(ndpi_struct, "Same seq on consecutive pkts\n");
        flow->rtp_stage = 0;
        flow->rtcp_stage = 0;
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        NDPI_EXCLUDE_PROTO_EXT(ndpi_struct, flow, NDPI_PROTOCOL_RTCP);
      } else {
        rtp_get_stream_type(flow->rtp[packet->packet_direction].payload_type,
			    &flow->flow_multimedia_types, NDPI_PROTOCOL_UNKNOWN);

        NDPI_LOG_INFO(ndpi_struct, "Found RTP\n");
        ndpi_int_rtp_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RTP);
      }
      return;
    }
    if(flow->rtp_stage == 0) {
      flow->rtp_seq[packet->packet_direction] = seq;
      flow->rtp_seq_set[packet->packet_direction] = 1;
    }
    flow->rtp_stage += 1;
  } else if(is_rtp == IS_RTCP && flow->rtp_stage > 0) {
    /* RTCP after (some) RTP. Keep looking for RTP */
  } else if(is_rtp == IS_RTCP && flow->rtp_stage == 0) {
    if(flow->rtcp_stage == 3) {
      NDPI_LOG_INFO(ndpi_struct, "Found RTCP\n");
      ndpi_int_rtp_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RTCP);
      return;
    }
    flow->rtcp_stage += 1;
  } else {
    if(flow->rtp_stage || flow->rtcp_stage) {
      u_int32_t unused;
      u_int16_t app_proto = NDPI_PROTOCOL_UNKNOWN;

      /* TODO: we should switch to the demultiplexing-code in stun dissector */
      if(is_stun(ndpi_struct, flow, &app_proto) != 0 &&
         !is_dtls(packet->payload, packet->payload_packet_len, &unused)) {
        flow->rtp_stage = 0;
        flow->rtcp_stage = 0;
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        NDPI_EXCLUDE_PROTO_EXT(ndpi_struct, flow, NDPI_PROTOCOL_RTCP);
      }
    }
  }
}

/* *************************************************************** */
/* https://datatracker.ietf.org/doc/html/rfc4571
 * message format for RTP/RTCP over TCP:
 *     0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      ---------------------------------------------------------------
 *     |             LENGTH            |  RTP or RTCP packet ...       |
 *      ---------------------------------------------------------------
 */
static void ndpi_search_rtp_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *payload = packet->payload;

  if(packet->payload_packet_len < 4){ /* (2) len field + (2) min rtp/rtcp*/
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    NDPI_EXCLUDE_PROTO_EXT(ndpi_struct, flow, NDPI_PROTOCOL_RTCP);
    return;
  }

  u_int16_t len = ntohs(get_u_int16_t(payload, 0));
  if(len + sizeof(len) != packet->payload_packet_len) { /*fragmented packets are not handled*/
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    NDPI_EXCLUDE_PROTO_EXT(ndpi_struct, flow, NDPI_PROTOCOL_RTCP);
  } else {
    ndpi_rtp_search(ndpi_struct, flow);
  }

}

/* *************************************************************** */
static void ndpi_search_rtp_udp(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t source = ntohs(packet->udp->source);
  u_int16_t dest = ntohs(packet->udp->dest);
  /*
   * XXX: not sure if rtp/rtcp over tcp will also mix with Ethereum
   * for now, will not add it unitl we have a false positive.
   */
  if((source == 30303) || (dest == 30303 /* Avoid to mix it with Ethereum that looks alike */)
     || (dest == 5355  /* LLMNR_PORT */)
     || (dest == 5353  /* MDNS_PORT */)
     || (dest == 9600  /* FINS_PORT */)
     || (dest <= 1023)){
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    NDPI_EXCLUDE_PROTO_EXT(ndpi_struct, flow, NDPI_PROTOCOL_RTCP);
    return;
  }
  ndpi_rtp_search(ndpi_struct, flow);
}

/* *************************************************************** */
static void ndpi_search_rtp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  if(packet->tcp != NULL) {
    ndpi_search_rtp_tcp(ndpi_struct, flow);
  } else {
    ndpi_search_rtp_udp(ndpi_struct, flow);
  }
}

/* *************************************************************** */

void init_rtp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("RTP", ndpi_struct, *id,
				      NDPI_PROTOCOL_RTP,
				      ndpi_search_rtp,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
