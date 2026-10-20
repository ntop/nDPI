/*
 * telnet.c
 *
 * Copyright (C) 2011-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TELNET

#include "ndpi_api.h"
#include "ndpi_private.h"

/* #define TELNET_DEBUG 1 */

#define TELNET_EVIDENCE_THRESHOLD 2
#define TELNET_IAC_SCAN_WINDOW    16

/* ************************************************************************ */

/*
 * Called for each extra packet after initial Telnet detection.
 * Extracts the username and password from the clear-text exchange.
 *
 * State machine:
 *   1. Wait for "login:" prompt  -> set username_found
 *   2. Accumulate client keystrokes until CR/LF -> set username_detected
 *   3. Wait for "password:" prompt -> set password_found
 *   4. Accumulate client keystrokes until CR/LF -> set password_detected
 *
 * Returns 1 to keep processing more packets, 0 when done.
 */
static int search_telnet_again(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int i;

#ifdef TELNET_DEBUG
  printf("==> %s() [%.*s][direction: %u]\n", __FUNCTION__,
         packet->payload_packet_len, packet->payload, packet->packet_direction);
#endif

  if(!packet->payload || packet->payload_packet_len == 0 || packet->payload[0] == 0xFF)
    return 1;

  if(flow->metadata.protos.telnet.username_detected) {
    /* Phase 3-4: collecting password */
    if(!flow->metadata.protos.telnet.password_found) {
      if(packet->payload_packet_len > 9 &&
         strncasecmp((char *)packet->payload, "password:", 9) == 0)
        flow->metadata.protos.telnet.password_found = 1;
      return 1;
    }

    if(packet->payload[0] == '\r' || packet->payload[0] == '\n') {
      if(!flow->metadata.protos.telnet.password_found)
        return 1;
      flow->metadata.protos.telnet.password_detected = 1;
      ndpi_set_risk(ndpi_struct, &flow->core, NDPI_CLEAR_TEXT_CREDENTIALS, "Found password");
      flow->metadata.protos.telnet.password[flow->metadata.protos.telnet.character_id] = '\0';
      return 0;
    }

    if(packet->packet_direction == 0) {
      for(i = 0; i < packet->payload_packet_len; i++) {
        if(flow->metadata.protos.telnet.character_id < (int)(sizeof(flow->metadata.protos.telnet.password) - 1))
          flow->metadata.protos.telnet.password[flow->metadata.protos.telnet.character_id++] = packet->payload[i];
      }
    }
    return 1;
  }

  /* Phase 1: waiting for the "login:" prompt */
  if(!flow->metadata.protos.telnet.username_found) {
    if(packet->payload_packet_len > 6 &&
       strncasecmp((char *)packet->payload, "login:", 6) == 0)
      flow->metadata.protos.telnet.username_found = 1;
    return 1;
  }

  /* Phase 2: "login:" seen — accumulate username until CR/LF */
  if(packet->payload[0] == '\r' || packet->payload[0] == '\n') {
    char buf[64];

    flow->metadata.protos.telnet.username_detected = 1;
    flow->metadata.protos.telnet.username[flow->metadata.protos.telnet.character_id] = '\0';
    flow->metadata.protos.telnet.character_id = 0;

    snprintf(buf, sizeof(buf), "Found Telnet username (%s)",
             flow->metadata.protos.telnet.username);
    ndpi_set_risk(ndpi_struct, &flow->core, NDPI_CLEAR_TEXT_CREDENTIALS, buf);
    return 1;
  }

  if(packet->packet_direction == 0) {
    for(i = 0; i < packet->payload_packet_len; i++) {
      if(flow->metadata.protos.telnet.character_id < (int)(sizeof(flow->metadata.protos.telnet.username) - 1)) {
        /* Skip trailing CR/LF; replace non-printable chars with '?' */
        if(i >= packet->payload_packet_len - 2 &&
           (packet->payload[i] == '\r' || packet->payload[i] == '\n'))
          continue;
        flow->metadata.protos.telnet.username[flow->metadata.protos.telnet.character_id++] =
          ndpi_isprint(packet->payload[i]) ? packet->payload[i] : '?';
      }
    }
  }

  return 1;
}

/* ************************************************************************ */

static void telnet_set_detected(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow) {
  flow->core.max_extra_packets_to_check = 64;
  flow->core.extra_packets_func = search_telnet_again;
  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_TELNET, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ************************************************************************ */

static inline u_int8_t is_iac_negotiation(u_int8_t cmd) {
  return (cmd >= 0xFB && cmd <= 0xFE) ? 1 : 0;
}

static inline u_int8_t is_iac_two_byte(u_int8_t cmd) {
  return (cmd >= 0xF0 && cmd <= 0xFA) ? 1 : 0;
}

/*
 * Scans the packet payload and counts valid IAC commands.
 *
 * Returns:
 *   0   - payload doesn't start with a valid IAC command, or an
 *         unknown/invalid command byte was found after some IAC
 *         (i.e. not Telnet);
 *   N>0 - number of valid commands found (including the first one).
 *
 * IAC command layout:
 *   IAC IAC               - escaped 0xFF, a literal data byte
 *   IAC <0xF0-0xFA>        - two-byte command
 *   IAC <0xFB-0xFE> <opt>  - three-byte command (negotiation)
 */
static u_int8_t count_iac(struct ndpi_packet_struct const * const packet) {
  u_int16_t max_pos, pos;
  u_int8_t count = 0;

#ifdef TELNET_DEBUG
  printf("==> %s()\n", __FUNCTION__);
#endif

  if(packet->payload_packet_len < 3) {
    return 0;
  }

  if(packet->payload[0] != 0xFF) {
    return 0;
  }

  if(packet->payload[1] != 0xFA && !is_iac_negotiation(packet->payload[1])) {
    return 0;
  }

  max_pos = packet->payload_packet_len;
  if(max_pos > TELNET_IAC_SCAN_WINDOW) {
    max_pos = TELNET_IAC_SCAN_WINDOW;
  }

  for(pos = 0; pos < max_pos; pos++) {
    u_int8_t cmd;

    if(packet->payload[pos] != 0xFF) {
      continue;
    }

    if(pos + 1 >= packet->payload_packet_len) {
      break; /* Truncated at the end of the payload, not an error */
    }

    cmd = packet->payload[pos + 1];

    if(cmd == 0xFF) {
      pos += 1;
      continue;
    }

    if(is_iac_two_byte(cmd)) {
      pos += 1;
      count++;
      continue;
    }

    if(is_iac_negotiation(cmd)) {
      if(pos + 2 >= packet->payload_packet_len) {
        break; /* Option byte truncated, tolerate it */
      }

      if(packet->payload[pos + 2] >= 0x28) {
        return 0;
      }

      pos += 2;
      count++;

      continue;
    }

    /* Unknown command after IAC -> not Telnet */
    return 0;
  }

  return count;
}

/* ************************************************************************ */

static void ndpi_search_telnet_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow) {
  NDPI_LOG_DBG(ndpi_struct, "search telnet\n");

  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  u_int16_t port23 = htons(23);

  u_int8_t n = count_iac(packet);

  if (n > 0) {
    /*
     * Fast-path detection: strong signal (multiple commands in one packet)
     * or well-known port -> detect immediately, no need to accumulate evidence.
     */
     if ((packet->tcp->source == port23 || packet->tcp->dest == port23) || n >= 2) {
        NDPI_LOG_INFO(ndpi_struct, "found Telnet (fast-path)\n");
        telnet_set_detected(ndpi_struct, flow);
        return;
     }

     /* Weak signal on a non-standard port -> accumulate evidence */
     if (flow->metadata.protos.telnet.evidence < TELNET_EVIDENCE_THRESHOLD) {
      flow->metadata.protos.telnet.evidence++;
     }

     if(flow->metadata.protos.telnet.evidence >= TELNET_EVIDENCE_THRESHOLD) {
      NDPI_LOG_INFO(ndpi_struct, "found Telnet (evidence threshold)\n");
      telnet_set_detected(ndpi_struct, flow);
      return;
     }
  }

  if(flow->core.packet_counter > 6) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  }
}

/* ************************************************************************ */

void init_telnet_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("Telnet", ndpi_struct,
                          ndpi_search_telnet_tcp,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          DISSECTOR_LICENSE_LGPL,
                          1, NDPI_PROTOCOL_TELNET);
}
