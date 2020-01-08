/*
 * rtp.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-20 - ntop.org
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


/* http://www.myskypelab.com/2014/05/microsoft-lync-wireshark-plugin.html */

static u_int8_t isValidMSRTPType(u_int8_t payloadType) {
  switch(payloadType) {
  case 0: /* G.711 u-Law */
  case 3: /* GSM 6.10 */
  case 4: /* G.723.1  */
  case 8: /* G.711 A-Law */
  case 9: /* G.722 */
  case 13: /* Comfort Noise */
  case 96: /* Dynamic RTP */
  case 97: /* Redundant Audio Data Payload */
  case 101: /* DTMF */
  case 103: /* SILK Narrowband */
  case 104: /* SILK Wideband */
  case 111: /* Siren */
  case 112: /* G.722.1 */
  case 114: /* RT Audio Wideband */
  case 115: /* RT Audio Narrowband */
  case 116: /* G.726 */
  case 117: /* G.722 */
  case 118: /* Comfort Noise Wideband */
  case 34: /* H.263 [MS-H26XPF] */
  case 121: /* RT Video */
  case 122: /* H.264 [MS-H264PF] */
  case 123: /* H.264 FEC [MS-H264PF] */
  case 127: /* x-data */
    return(1 /* RTP */);
    break;

  case 200: /* RTCP PACKET SENDER */
  case 201: /* RTCP PACKET RECEIVER */
  case 202: /* RTCP Source Description */
  case 203: /* RTCP Bye */
    return(2 /* RTCP */);
    break;

  default:
    return(0);
  }
}

/* *************************************************************** */

static void ndpi_rtp_search(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow,
			    const u_int8_t * payload, const u_int16_t payload_len) {
  NDPI_LOG_DBG(ndpi_struct, "search RTP\n");

  if((payload_len < 2) || flow->protos.stun_ssl.stun.num_binding_requests) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  //struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t payloadType, payload_type = payload[1] & 0x7F;

  /* Check whether this is an RTP flow */
  if((payload_len >= 12)
     && (((payload[0] & 0xFF) == 0x80) || ((payload[0] & 0xFF) == 0xA0)) /* RTP magic byte[1] */
     && ((payload_type < 72) || (payload_type > 76))
     && ((payload_type <= 34)
	 || ((payload_type >= 96) && (payload_type <= 127))
	 /* http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml */
       )
    ) {
    NDPI_LOG_INFO(ndpi_struct, "Found RTP\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RTP, NDPI_PROTOCOL_UNKNOWN);
    return;
  } else if((payload_len >= 12)
	    && (((payload[0] & 0xFF) == 0x80) || ((payload[0] & 0xFF) == 0xA0)) /* RTP magic byte[1] */
	    && (payloadType = isValidMSRTPType(payload[1] & 0xFF))) {
    if(payloadType == 1 /* RTP */) {
      NDPI_LOG_INFO(ndpi_struct, "Found Skype for Business (former MS Lync)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE, NDPI_PROTOCOL_UNKNOWN);
      return;
    } else /* RTCP */ {
#if 0
      /* If it's RTCP the RTCP decoder will catch it */
      NDPI_LOG_INFO(ndpi_struct, "Found MS RTCP\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RTCP, NDPI_PROTOCOL_UNKNOWN);
      return;
#endif
    }
  }

  /* No luck this time */
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* *************************************************************** */

void ndpi_search_rtp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t source = ntohs(packet->udp->source);
  u_int16_t dest = ntohs(packet->udp->dest);
  
  // printf("==> %s()\n", __FUNCTION__);
  
  /* printf("*** %s(pkt=%d)\n", __FUNCTION__, flow->packet_counter); */

  if((packet->udp != NULL)
     && (source != 30303) && (dest != 30303 /* Avoid to mix it with Ethereum that looks alike */)
     && (dest > 1023)
     )
    ndpi_rtp_search(ndpi_struct, flow, packet->payload, packet->payload_packet_len);
}

/* *************************************************************** */

#if 0
/* Original (messy) OpenDPI code */

#define RTP_MAX_OUT_OF_ORDER 11

static void ndpi_int_rtp_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RTP, NDPI_PROTOCOL_UNKNOWN);
}

/*
 * maintenance of current highest sequence number, cycle count, packet counter
 * adapted from RFC3550 Appendix A.1
 *
 * In their formulation, it is not possible to represent "no packets sent yet". This is fixed here by defining
 * baseseq to be the sequence number of the first packet minus 1 (in other words, the sequence number of the
 * zeroth packet).
 *
 * Note: As described in the RFC, the number of packets received includes retransmitted packets.
 * This means the "packets lost" count (seq_num-isn+1)-received can become negative.
 *
 * include_current_packet should be
 *   1, if the current packet should count towards the total, or
 *   0, if it it regarded as belonging to the previous reporting interval
 */

#if !defined(WIN32)
static inline
#elif defined(MINGW_GCC)
__mingw_forceinline static
#else
__forceinline static
#endif
void init_seq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow,
	      u_int8_t direction, u_int16_t seq, u_int8_t include_current_packet)
{
  flow->rtp_seqnum[direction] = seq;
  NDPI_LOG_DBG(ndpi_struct, "rtp_seqnum[%u] = %u\n", direction, seq);
}

/* returns difference between old and new highest sequence number */

#if !defined(WIN32)
static inline
#elif defined(MINGW_GCC)
__mingw_forceinline static
#else
__forceinline static
#endif
u_int16_t update_seq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow,
		     u_int8_t direction, u_int16_t seq)
{
  u_int16_t delta = seq - flow->rtp_seqnum[direction];


  if(delta < RTP_MAX_OUT_OF_ORDER) {	/* in order, with permissible gap */
    flow->rtp_seqnum[direction] = seq;
    NDPI_LOG_DBG(ndpi_struct, "rtp_seqnum[%u] = %u (increased by %u)\n",
		 direction, seq, delta);
    return delta;
  } else {
    NDPI_LOG_DBG(ndpi_struct, "retransmission (dir %u, seqnum %u)\n",
		 direction, seq);
    return 0;
  }
}

static void ndpi_rtp_search(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow,
			    const u_int8_t * payload, const u_int16_t payload_len)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  u_int8_t stage;
  u_int16_t seqnum = ntohs(get_u_int16_t(payload, 2));

  NDPI_LOG_DBG(ndpi_struct, "search rtp\n");

  if(payload_len == 4 && get_u_int32_t(packet->payload, 0) == 0 && flow->packet_counter < 8) {
    NDPI_LOG_DBG(ndpi_struct, "need next packet, maybe ClearSea out calls\n");
    return;
  }

  if(payload_len == 5 && memcmp(payload, "hello", 5) == 0) {
    NDPI_LOG_DBG(ndpi_struct,
		 "need next packet, initial hello packet of SIP out calls.\n");
    return;
  }

  if(payload_len == 1 && payload[0] == 0) {
    NDPI_LOG_DBG(ndpi_struct,
		 "need next packet, payload_packet_len == 1 && payload[0] == 0.\n");
    return;
  }

  if(payload_len == 3 && memcmp(payload, "png", 3) == 0) {
    /* weird packet found in Ninja GlobalIP trace */
    NDPI_LOG_DBG(ndpi_struct, "skipping packet with len = 3 and png payload\n");
    return;
  }

  if(payload_len < 12) {
    NDPI_LOG_DBG(ndpi_struct, "minimal packet size for rtp packets: 12\n");
    goto exclude_rtp;
  }

  if(payload_len == 12 && get_u_int32_t(payload, 0) == 0 && get_u_int32_t(payload, 4) == 0 && get_u_int32_t(payload, 8) == 0) {
    NDPI_LOG_DBG(ndpi_struct, "skipping packet with len = 12 and only 0-bytes\n");
    return;
  }

  if((payload[0] & 0xc0) == 0xc0 || (payload[0] & 0xc0) == 0x40 || (payload[0] & 0xc0) == 0x00) {
    NDPI_LOG_DBG(ndpi_struct, "version = 3 || 1 || 0, maybe first rtp packet\n");
    return;
  }

  if((payload[0] & 0xc0) != 0x80) {
    NDPI_LOG_DBG(ndpi_struct, "rtp version must be 2, first two bits of a packets must be 10\n");
    goto exclude_rtp;
  }

  /* rtp_payload_type are the last seven bits of the second byte */
  if(flow->rtp_payload_type[packet->packet_direction] != (payload[1] & 0x7F)) {
    NDPI_LOG_DBG(ndpi_struct, "payload_type has changed, reset stages\n");
    packet->packet_direction == 0 ? (flow->rtp_stage1 = 0) : (flow->rtp_stage2 = 0);
  }
  /* first bit of first byte is not part of payload_type */
  flow->rtp_payload_type[packet->packet_direction] = payload[1] & 0x7F;

  stage = (packet->packet_direction == 0 ? flow->rtp_stage1 : flow->rtp_stage2);

  if(stage > 0) {
    NDPI_LOG_DBG(ndpi_struct, "stage = %u\n", packet->packet_direction == 0 ? flow->rtp_stage1 : flow->rtp_stage2);
    if(flow->rtp_ssid[packet->packet_direction] != get_u_int32_t(payload, 8)) {
      NDPI_LOG_DBG(ndpi_struct, "ssid has changed, goto exclude rtp\n");
      goto exclude_rtp;
    }

    if(seqnum == flow->rtp_seqnum[packet->packet_direction]) {
      NDPI_LOG_DBG(ndpi_struct, "maybe \"retransmission\", need next packet\n");
      return;
    } else if((u_int16_t) (seqnum - flow->rtp_seqnum[packet->packet_direction]) < RTP_MAX_OUT_OF_ORDER) {
      NDPI_LOG_DBG(ndpi_struct,
		   "new packet has larger sequence number (within valid range)\n");
      update_seq(ndpi_struct, flow, packet->packet_direction, seqnum);
    } else if((u_int16_t) (flow->rtp_seqnum[packet->packet_direction] - seqnum) < RTP_MAX_OUT_OF_ORDER) {
      NDPI_LOG_DBG(ndpi_struct,
		   "new packet has smaller sequence number (within valid range)\n");
      init_seq(ndpi_struct, flow, packet->packet_direction, seqnum, 1);
    } else {
      NDPI_LOG_DBG(ndpi_struct,
		   "sequence number diff is too big, goto exclude rtp.\n");
      goto exclude_rtp;
    }
  } else {
    NDPI_LOG_DBG(ndpi_struct, "rtp_ssid[%u] = %u\n", packet->packet_direction,
		 flow->rtp_ssid[packet->packet_direction]);
    flow->rtp_ssid[packet->packet_direction] = get_u_int32_t(payload, 8);
    if(flow->packet_counter < 3) {
      NDPI_LOG_DBG(ndpi_struct, "packet_counter < 3, need next packet\n");
    }
    init_seq(ndpi_struct, flow, packet->packet_direction, seqnum, 1);
  }
  if(seqnum <= 3) {
    NDPI_LOG_DBG(ndpi_struct, "sequence_number = %u, too small, need next packet, return\n", seqnum);
    return;
  }

  if(stage == 3) {
    NDPI_LOG_DBG(ndpi_struct, "add connection I\n");
    ndpi_int_rtp_add_connection(ndpi_struct, flow);
  } else {
    packet->packet_direction == 0 ? flow->rtp_stage1++ : flow->rtp_stage2++;
    NDPI_LOG_DBG(ndpi_struct, "stage[%u]++; need next packet\n",
		 packet->packet_direction);
  }
  return;

exclude_rtp:
  if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_STUN
     || /* packet->real_protocol_read_only == NDPI_PROTOCOL_STUN */) {
    NDPI_LOG_DBG(ndpi_struct, "STUN: is detected, need next packet\n");
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* *************************************************************** */

void ndpi_search_rtp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;


  if(packet->udp) {
    ndpi_rtp_search(ndpi_struct, flow, packet->payload, packet->payload_packet_len);
  } else if(packet->tcp) {

    /* skip special packets seen at yahoo traces */
    if(packet->payload_packet_len >= 20 && ntohs(get_u_int16_t(packet->payload, 2)) + 20 == packet->payload_packet_len &&
       packet->payload[0] == 0x90 && packet->payload[1] >= 0x01 && packet->payload[1] <= 0x07) {
      if(flow->packet_counter == 2)
	flow->l4.tcp.rtp_special_packets_seen = 1;
      NDPI_LOG_DBG(ndpi_struct,
		   "skipping STUN-like, special yahoo packets with payload[0] == 0x90.\n");
      return;
    }

    /* TODO the rtp detection sometimes doesn't exclude rtp
     * so for TCP flows only run the detection if STUN has been
     * detected (or RTP is already detected)
     * If flows will be seen which start directly with RTP
     * we can remove this restriction
     */

    if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_STUN
       || packet->detected_protocol_stack[0] == NDPI_PROTOCOL_RTP) {

      /* RTP may be encapsulated in TCP packets */

      if(packet->payload_packet_len >= 2 && ntohs(get_u_int16_t(packet->payload, 0)) + 2 == packet->payload_packet_len) {

	/* TODO there could be several RTP packets in a single TCP packet so maybe the detection could be
	 * improved by checking only the RTP packet of given length */

	ndpi_rtp_search(ndpi_struct, flow, packet->payload + 2, packet->payload_packet_len - 2);

	return;
      }
    }

    if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN && flow->l4.tcp.rtp_special_packets_seen == 1) {

      if(packet->payload_packet_len >= 4 && ntohl(get_u_int32_t(packet->payload, 0)) + 4 == packet->payload_packet_len) {

	/* TODO there could be several RTP packets in a single TCP packet so maybe the detection could be
	 * improved by checking only the RTP packet of given length */

	ndpi_rtp_search(ndpi_struct, flow, packet->payload + 4, packet->payload_packet_len - 4);

	return;
      }
    }

    if(NDPI_FLOW_PROTOCOL_EXCLUDED(ndpi_struct, flow, NDPI_PROTOCOL_STUN)) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    } else {
      NDPI_LOG_DBG(ndpi_struct, "STUN not yet excluded, need next packet\n");
    }
  }
}
#endif

/* *************************************************************** */

void init_rtp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("RTP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_RTP,
				      ndpi_search_rtp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
