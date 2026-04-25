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

/* ************************************************************************ */

/*
 * Called for each extra packet after initial Telnet detection.
 * Extracts the username and password from the clear-text exchange.
 *
 * State machine:
 *   1. Wait for "login:" prompt  → set username_found
 *   2. Accumulate client keystrokes until CR/LF → set username_detected
 *   3. Wait for "password:" prompt → set password_found
 *   4. Accumulate client keystrokes until CR/LF → set password_detected
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

  if(flow->protos.telnet.username_detected) {
    /* Phase 3-4: collecting password */
    if(!flow->protos.telnet.password_found) {
      if(packet->payload_packet_len > 9 &&
         strncasecmp((char *)packet->payload, "password:", 9) == 0)
        flow->protos.telnet.password_found = 1;
      return 1;
    }

    if(packet->payload[0] == '\r' || packet->payload[0] == '\n') {
      if(!flow->protos.telnet.password_found)
        return 1;
      flow->protos.telnet.password_detected = 1;
      ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, "Found password");
      flow->protos.telnet.password[flow->protos.telnet.character_id] = '\0';
      return 0;
    }

    if(packet->packet_direction == 0) {
      for(i = 0; i < packet->payload_packet_len; i++) {
        if(flow->protos.telnet.character_id < (int)(sizeof(flow->protos.telnet.password) - 1))
          flow->protos.telnet.password[flow->protos.telnet.character_id++] = packet->payload[i];
      }
    }
    return 1;
  }

  /* Phase 1: waiting for the "login:" prompt */
  if(!flow->protos.telnet.username_found) {
    if(packet->payload_packet_len > 6 &&
       strncasecmp((char *)packet->payload, "login:", 6) == 0)
      flow->protos.telnet.username_found = 1;
    return 1;
  }

  /* Phase 2: "login:" seen — accumulate username until CR/LF */
  if(packet->payload[0] == '\r' || packet->payload[0] == '\n') {
    char buf[64];

    flow->protos.telnet.username_detected = 1;
    flow->protos.telnet.username[flow->protos.telnet.character_id] = '\0';
    flow->protos.telnet.character_id = 0;

    snprintf(buf, sizeof(buf), "Found Telnet username (%s)",
             flow->protos.telnet.username);
    ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, buf);
    return 1;
  }

  if(packet->packet_direction == 0) {
    for(i = 0; i < packet->payload_packet_len; i++) {
      if(flow->protos.telnet.character_id < (int)(sizeof(flow->protos.telnet.username) - 1)) {
        /* Skip trailing CR/LF; replace non-printable chars with '?' */
        if(i >= packet->payload_packet_len - 2 &&
           (packet->payload[i] == '\r' || packet->payload[i] == '\n'))
          continue;
        flow->protos.telnet.username[flow->protos.telnet.character_id++] =
          ndpi_isprint(packet->payload[i]) ? packet->payload[i] : '?';
      }
    }
  }

  return 1;
}

/* ************************************************************************ */

static void telnet_set_detected(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow) {
  flow->max_extra_packets_to_check = 64;
  flow->extra_packets_func = search_telnet_again;
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_TELNET, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ************************************************************************ */

/*
 * Returns 1 if the packet starts with a valid Telnet IAC (0xFF) command
 * sequence and any subsequent bytes also form valid IAC triplets.
 *
 * IAC command format:
 *   Byte 0:    0xFF  (IAC)
 *   Byte 1:    command byte (0xF0–0xFE, not 0xFF)
 *   Byte 2:    option byte (≤ 0x28, only required for commands 0xFB–0xFE)
 */
#if !defined(WIN32)
static inline
#elif defined(MINGW_GCC)
__mingw_forceinline static
#else
__forceinline static
#endif
u_int8_t search_iac(struct ndpi_detection_module_struct *ndpi_struct) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t pos;

#ifdef TELNET_DEBUG
  printf("==> %s()\n", __FUNCTION__);
#endif

  if(packet->payload_packet_len < 3)
    return 0;

  /* First triplet must start with IAC (0xFF), followed by a command
     byte strictly between 0xF9 and 0xFF, and an option byte < 0x28. */
  if(!(packet->payload[0] == 0xFF &&
       packet->payload[1] > 0xF9 &&
       packet->payload[1] != 0xFF &&
       packet->payload[2] < 0x28))
    return 0;

  /* Walk subsequent triplets; each must also be a valid IAC command. */
  for(pos = 3; pos < packet->payload_packet_len - 2; pos += 3) {
    u_int8_t b0 = packet->payload[pos];
    u_int8_t b1 = packet->payload[pos + 1];
    u_int8_t b2 = packet->payload[pos + 2];

    /* Non-IAC byte is acceptable between commands */
    if(b0 != 0xFF)
      continue;

    /* Two-byte IAC commands (GA, EL, EC, AO, AYT, BRK, NOP, SE): 0xF0–0xFA */
    if(b1 >= 0xF0 && b1 <= 0xFA)
      continue;

    /* Three-byte IAC commands (WILL/WONT/DO/DONT): 0xFB–0xFE with option ≤ 0x28 */
    if(b1 >= 0xFB && b1 != 0xFF && b2 <= 0x28)
      continue;

    return 0;
  }

  return 1;
}

/* ************************************************************************ */

static void ndpi_search_telnet_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow) {
  NDPI_LOG_DBG(ndpi_struct, "search telnet\n");

  if(search_iac(ndpi_struct)) {
    NDPI_LOG_INFO(ndpi_struct, "found telnet\n");
    telnet_set_detected(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

/* ************************************************************************ */

void init_telnet_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("Telnet", ndpi_struct,
                          ndpi_search_telnet_tcp,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_TELNET);
}
