/*
 * s7comm.c
 *
 * Copyright (C) 2023 - ntop.org
 * Copyright (C) 2023 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_S7COMM

#include "ndpi_api.h"
#include "ndpi_private.h"

#define TPKT_PORT               102
#define S7COMM_MAGIC_BYTE       0x32
#define S7COMM_PLUS_MAGIC_BYTE  0x72

/* S7Comm Message Types */
#define S7COMM_MSG_JOB          0x01  /* Request */
#define S7COMM_MSG_ACK          0x02  /* Acknowledgment without data */
#define S7COMM_MSG_ACK_DATA     0x03  /* Response with data */
#define S7COMM_MSG_USERDATA     0x07  /* UserData (programming/debugging) */

/* S7Comm Function Codes (in Job messages) */
#define S7COMM_FUNC_READ_VAR    0x04  /* Read Var */
#define S7COMM_FUNC_WRITE_VAR   0x05  /* Write Var */
#define S7COMM_FUNC_DOWNLOAD    0x1A  /* Download block */
#define S7COMM_FUNC_UPLOAD      0x1B  /* Upload block */
#define S7COMM_FUNC_PLC_CONTROL 0x28  /* PLC Control */
#define S7COMM_FUNC_PLC_STOP    0x29  /* PLC Stop */
#define S7COMM_FUNC_SETUP_COMM  0xF0  /* Setup Communication */

/* S7Comm header offsets (after TPKT + COTP) */
#define S7COMM_HEADER_PROTOCOL_ID   0  /* Protocol ID (0x32) */
#define S7COMM_HEADER_MSG_TYPE      1  /* Message type */
#define S7COMM_HEADER_RESERVED      2  /* Reserved (2 bytes) */
#define S7COMM_HEADER_PDU_REF       4  /* PDU reference (2 bytes) */
#define S7COMM_HEADER_PARAM_LEN     6  /* Parameter length (2 bytes) */
#define S7COMM_HEADER_DATA_LEN      8  /* Data length (2 bytes) */
#define S7COMM_HEADER_ERR_CLASS    10  /* Error class (1 bytes); only in Ack or Ack-Data messages */
#define S7COMM_HEADER_ERR_CODE     11  /* Error code (1 bytes); only in Ack or Ack-Data messages */
#define S7COMM_HEADER_MIN_LEN      10  /* Minimum header length */
#define S7COMM_HEADER_MIN_LEN_ACKS 12  /* Minimum header length (for Ack or Ack-Data messages) */

/* For Ack_Data messages, there's an error code before parameters */
#define S7COMM_ACK_DATA_ERROR_CODE  10 /* Error code (2 bytes, only in Ack_Data) */
#define S7COMM_ACK_DATA_PARAM_START 12 /* Parameter start for Ack_Data */
#define S7COMM_JOB_PARAM_START      10 /* Parameter start for Job */
#define S7COMM_USERDATA_PARAM_START 10 /* Parameter start for Userdata */

/* Helper function to parse S7Comm message and update statistics */
static void ndpi_parse_s7comm_message(struct ndpi_detection_module_struct *ndpi_struct,
                                      struct ndpi_flow_struct *flow,
                                      const u_int8_t *s7comm_header,
                                      u_int16_t s7comm_len)
{
  u_int8_t msg_type;
  u_int16_t param_len;
  u_int8_t function_code;

  /* Need at least the minimum S7Comm header */
  if (s7comm_len < S7COMM_HEADER_MIN_LEN)
    return;

  if(flow->monit == NULL)
    flow->monit = ndpi_calloc(1, sizeof(struct ndpi_metadata_monitoring));

  msg_type = s7comm_header[S7COMM_HEADER_MSG_TYPE];
  param_len = ntohs(get_u_int16_t(s7comm_header, S7COMM_HEADER_PARAM_LEN));

  /* Ack and Ack_data header is longer */
  if((msg_type == S7COMM_MSG_ACK || msg_type == S7COMM_MSG_ACK_DATA) &&
     s7comm_len < S7COMM_HEADER_MIN_LEN_ACKS)
    return;

  NDPI_LOG_DBG2(ndpi_struct, "S7Comm msg_type=0x%02x, param_len=%u\n", msg_type, param_len);

  /* Update message type counters */
  switch(msg_type) {
    case S7COMM_MSG_JOB:
      flow->protos.s7comm.num_requests++;

      /* Parse function code from parameter section for Job messages */
      if (param_len > 0 && s7comm_len > S7COMM_JOB_PARAM_START) {
        function_code = s7comm_header[S7COMM_JOB_PARAM_START];
        NDPI_LOG_DBG2(ndpi_struct, "S7Comm Job function_code=0x%02x\n", function_code);

        /* Update function-specific counters */
        switch(function_code) {
          case S7COMM_FUNC_READ_VAR:
            flow->protos.s7comm.num_read_var++;
            break;
          case S7COMM_FUNC_WRITE_VAR:
            flow->protos.s7comm.num_write_var++;
            break;
          case S7COMM_FUNC_SETUP_COMM:
            flow->protos.s7comm.num_setup_comm++;
            break;
          case S7COMM_FUNC_DOWNLOAD:
            flow->protos.s7comm.num_download++;
            break;
          case S7COMM_FUNC_UPLOAD:
            flow->protos.s7comm.num_upload++;
            break;
          case S7COMM_FUNC_PLC_CONTROL:
            flow->protos.s7comm.num_plc_control++;
            break;
          case S7COMM_FUNC_PLC_STOP:
            flow->protos.s7comm.num_plc_stop++;
            break;
          default:
            flow->protos.s7comm.num_other_funcs++;
            break;
        }
      }
      break;

    case S7COMM_MSG_ACK:
      flow->protos.s7comm.num_acks++;
      break;

    case S7COMM_MSG_ACK_DATA:
      flow->protos.s7comm.num_responses++;
      /* Could also parse the function code from Ack_Data if needed */
      if (param_len > 0 && s7comm_len > S7COMM_ACK_DATA_PARAM_START) {
        function_code = s7comm_header[S7COMM_ACK_DATA_PARAM_START];
        NDPI_LOG_DBG2(ndpi_struct, "S7Comm Ack_Data function_code=0x%02x\n", function_code);
      }
      break;

    case S7COMM_MSG_USERDATA:
      flow->protos.s7comm.num_userdata++;
      break;

    default:
      NDPI_LOG_DBG2(ndpi_struct, "S7Comm unknown msg_type=0x%02x\n", msg_type);
      break;
  }
}

/* Callback function for continuous packet processing after detection */
static int ndpi_search_s7comm_again(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  u_int8_t s7comm_offset = 7; /* TPKT(4) + COTP(3) = offset 7 for S7Comm header */

  NDPI_LOG_DBG2(ndpi_struct, "S7Comm extra dissection\n");

  /* Skip retransmissions and empty packets */
  if (packet->tcp_retransmission || packet->payload_packet_len == 0)
    return 1; /* Continue extra dissection */

  /* Parse S7Comm messages for statistics throughout the session */
  if (tpkt_verify_hdr(packet) && (packet->payload_packet_len > s7comm_offset + S7COMM_HEADER_MIN_LEN)) {
    if (packet->payload[s7comm_offset] == S7COMM_MAGIC_BYTE) {
      ndpi_parse_s7comm_message(ndpi_struct, flow,
                                &packet->payload[s7comm_offset],
                                packet->payload_packet_len - s7comm_offset);
    }
  }

  return 1; /* Continue extra dissection */
}

static void ndpi_search_s7comm(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  u_int8_t s7comm_offset = 7; /* TPKT(4) + COTP(3) = offset 7 for S7Comm header */

  NDPI_LOG_DBG(ndpi_struct, "search S7comm\n");

  /* Initial detection */
  if (tpkt_verify_hdr(packet) && (packet->payload_packet_len > 17) &&
      ((packet->tcp->source == htons(TPKT_PORT)) ||
       (packet->tcp->dest == htons(TPKT_PORT))))
  {
    if (packet->payload[s7comm_offset] == S7COMM_PLUS_MAGIC_BYTE) {
      const u_int16_t trail_byte_offset = packet->payload_packet_len - 4;
      if (packet->payload[trail_byte_offset] == S7COMM_PLUS_MAGIC_BYTE) {
        NDPI_LOG_INFO(ndpi_struct, "found S7CommPlus\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_S7COMM_PLUS,
                                   NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
        /* TODO: monitoring? */
        return;
      }
    } else if (packet->payload[s7comm_offset] == S7COMM_MAGIC_BYTE) {
      if (((packet->payload[s7comm_offset + 1] <= 0x03) || (packet->payload[s7comm_offset + 1] == 0x07)) &&
          (get_u_int16_t(packet->payload, s7comm_offset + 2) == 0))
      {
        NDPI_LOG_INFO(ndpi_struct, "found S7Comm\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_S7COMM,
                                   NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);

        if(is_monitoring_enabled(ndpi_struct, NDPI_PROTOCOL_S7COMM)) {
          /* Parse this first message for statistics.
           * It makes sense only in monitoring */
          ndpi_parse_s7comm_message(ndpi_struct, flow,
                                    &packet->payload[s7comm_offset],
                                    packet->payload_packet_len - s7comm_offset);

          NDPI_LOG_DBG(ndpi_struct, "Enabled monitoring\n");
          flow->state = NDPI_STATE_MONITORING;
          /* No extra dissection, we move directly to monitor state */
          flow->extra_packets_func = ndpi_search_s7comm_again;
        }
        return;
      }
    }
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_s7comm_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("S7Comm", ndpi_struct,
                     ndpi_search_s7comm,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_S7COMM);
}
