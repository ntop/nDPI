/*
 * syslog.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SYSLOG

#include "ndpi_api.h"
#include "ndpi_private.h"

static void syslog_set_detected(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_SYSLOG, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ************************************************************************ */

/*
 * Syslog message format (RFC 3164):
 *   <PRI>HEADER MSG
 *
 * PRI = '<' followed by 1-3 decimal digits followed by '>'
 * HEADER begins with an optional space, then an alphanumeric hostname/tag
 * that may end with ' ', ':', '=', '[', or '-'.
 * If a ':' is found, it must be followed by a space.
 */
static void ndpi_search_syslog(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t i;

  NDPI_LOG_DBG(ndpi_struct, "search syslog\n");

  if(packet->payload_packet_len <= 20 || packet->payload[0] != '<') {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  NDPI_LOG_DBG2(ndpi_struct, "checked len>20 and first symbol=<\n");

  /* Read the numeric priority value: 1 to 3 digits */
  for(i = 1; i <= 3; i++) {
    if(packet->payload[i] < '0' || packet->payload[i] > '9')
      break;
  }

  NDPI_LOG_DBG2(ndpi_struct, "read symbols while the symbol is a number.\n");

  /* Priority value must be closed by '>' */
  if(packet->payload[i++] != '>') {
    NDPI_LOG_DBG(ndpi_struct, "excluded, there is no > following the number\n");
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  NDPI_LOG_DBG2(ndpi_struct, "a > following the number\n");

  /* An optional space may follow the '>' */
  if(packet->payload[i] == 0x20) {
    NDPI_LOG_DBG2(ndpi_struct, "a blank following the >: increment i\n");
    i++;
  } else {
    NDPI_LOG_DBG2(ndpi_struct, "no blank following the >: do nothing\n");
  }

  /* Walk the hostname/tag: alphanumeric chars are valid; break on
     recognised delimiters; anything else is not syslog. */
  while(i < packet->payload_packet_len - 1) {
    if(ndpi_isalnum(packet->payload[i])) {
      i++;
      continue;
    }
    if(packet->payload[i] == ' ' || packet->payload[i] == ':' ||
       packet->payload[i] == '=' || packet->payload[i] == '[' ||
       packet->payload[i] == '-')
      break;

    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* If we stopped on ':', the next character must be a space */
  if(packet->payload[i] == ':') {
    if(++i >= packet->payload_packet_len || packet->payload[i] != ' ') {
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
      return;
    }
  }

  NDPI_LOG_INFO(ndpi_struct, "found syslog\n");
  syslog_set_detected(ndpi_struct, flow);
}

/* ************************************************************************ */

void init_syslog_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("Syslog", ndpi_struct,
                          ndpi_search_syslog,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_SYSLOG);
}
