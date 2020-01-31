/*
 * memcached.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-20 - ntop.org
 * Copyright (C) 2018 - eGloo Incorporated
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

#define NDPI_CURRENT_PROTO      NDPI_PROTOCOL_MEMCACHED

#include "ndpi_api.h"

#define MCDC_SET                "set "
#define MCDC_SET_LEN            (sizeof(MCDC_SET) - 1)
#define MCDC_ADD                "add "
#define MCDC_ADD_LEN            (sizeof(MCDC_ADD) - 1)
#define MCDC_REPLACE            "replace "
#define MCDC_REPLACE_LEN        (sizeof(MCDC_REPLACE) - 1)
#define MCDC_APPEND             "append "
#define MCDC_APPEND_LEN         (sizeof(MCDC_APPEND) - 1)
#define MCDC_PREPEND            "prepend "
#define MCDC_PREPEND_LEN        (sizeof(MCDC_PREPEND) - 1)
#define MCDC_CAS                "cas "
#define MCDC_CAS_LEN            (sizeof(MCDC_CAS) - 1)
#define MCDC_GET                "get "
#define MCDC_GET_LEN            (sizeof(MCDC_GET) - 1)
#define MCDC_GETS               "gets "
#define MCDC_GETS_LEN           (sizeof(MCDC_GETS) - 1)
#define MCDC_DELETE             "delete "
#define MCDC_DELETE_LEN         (sizeof(MCDC_DELETE) - 1)
#define MCDC_INCR               "incr "
#define MCDC_INCR_LEN           (sizeof(MCDC_INCR) - 1)
#define MCDC_DECR               "decr "
#define MCDC_DECR_LEN           (sizeof(MCDC_DECR) - 1)
#define MCDC_TOUCH              "touch "
#define MCDC_TOUCH_LEN          (sizeof(MCDC_TOUCH) - 1)
#define MCDC_GAT                "gat "
#define MCDC_GAT_LEN            (sizeof(MCDC_GAT) - 1)
#define MCDC_GATS               "gats "
#define MCDC_GATS_LEN           (sizeof(MCDC_GATS) - 1)
#define MCDC_STATS              "stats"
#define MCDC_STATS_LEN          (sizeof(MCDC_STATS) - 1)

#define MCDR_ERROR              "ERROR\r\n"
#define MCDR_ERROR_LEN          (sizeof(MCDR_ERROR) - 1)
#define MCDR_CLIENT_ERROR       "CLIENT_ERROR "
#define MCDR_CLIENT_ERROR_LEN   (sizeof(MCDR_CLIENT_ERROR) - 1)
#define MCDR_SERVER_ERROR       "SERVER_ERROR "
#define MCDR_SERVER_ERROR_LEN   (sizeof(MCDR_SERVER_ERROR) - 1)
#define MCDR_STORED             "STORED\r\n"
#define MCDR_STORED_LEN         (sizeof(MCDR_STORED) - 1)
#define MCDR_NOT_STORED         "NOT_STORED\r\n"
#define MCDR_NOT_STORED_LEN     (sizeof(MCDR_NOT_STORED) - 1)
#define MCDR_EXISTS             "EXISTS\r\n"
#define MCDR_EXISTS_LEN         (sizeof(MCDR_EXISTS) - 1)
#define MCDR_NOT_FOUND          "NOT_FOUND\r\n"
#define MCDR_NOT_FOUND_LEN      (sizeof(MCDR_NOT_FOUND) - 1)
#define MCDR_END                "END\r\n"
#define MCDR_END_LEN            (sizeof(MCDR_END) - 1)
#define MCDR_DELETED            "DELETED\r\n"
#define MCDR_DELETED_LEN        (sizeof(MCDR_DELETED) - 1)
#define MCDR_TOUCHED            "TOUCHED\r\n"
#define MCDR_TOUCHED_LEN        (sizeof(MCDR_TOUCHED) - 1)
#define MCDR_STAT               "STAT "
#define MCDR_STAT_LEN           (sizeof(MCDR_STAT) - 1)

#define MEMCACHED_UDP_HDR_LEN   8
#define MEMCACHED_MIN_LEN       MCDR_END_LEN
#define MEMCACHED_MIN_UDP_LEN   (MEMCACHED_MIN_LEN + MEMCACHED_UDP_HDR_LEN)

#define MEMCACHED_MIN_MATCH     2 /* Minimum number of command/responses required */

#define MEMCACHED_MATCH(cr)     (cr ## _LEN > length || memcmp(offset, cr, cr ## _LEN))

static void ndpi_int_memcached_add_connection(struct ndpi_detection_module_struct
					      *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found memcached\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
			     NDPI_PROTOCOL_MEMCACHED, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_memcached(
			   struct ndpi_detection_module_struct *ndpi_struct,
			   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  const u_int8_t *offset = packet->payload;
  u_int16_t length = packet->payload_packet_len;
  u_int8_t *matches;

  NDPI_LOG_DBG(ndpi_struct, "search memcached\n");

  if (packet->tcp != NULL) {
    if (packet->payload_packet_len < MEMCACHED_MIN_LEN) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    matches = &flow->l4.tcp.memcached_matches;
  }
  else if (packet->udp != NULL) {
    if (packet->payload_packet_len < MEMCACHED_MIN_UDP_LEN) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    if ((offset[4] == 0x00 && offset[5] == 0x00) ||
	offset[6] != 0x00 || offset[7] != 0x00) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    offset += MEMCACHED_UDP_HDR_LEN;
    length -= MEMCACHED_UDP_HDR_LEN;
    matches = &flow->l4.udp.memcached_matches;
  }
  else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /* grep MCD memcached.c |\
   *  egrep -v '(LEN|MATCH)' |\
   *  sed -e 's/^#define //g' |\
   *  awk '{ printf "else if (! MEMCACHED_MATCH(%s)) *matches += 1;\n",$1 }' */

  if (! MEMCACHED_MATCH(MCDC_SET)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_ADD)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_REPLACE)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_APPEND)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_PREPEND)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_CAS)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_GET)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_GETS)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_DELETE)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_INCR)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_DECR)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_TOUCH)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_GAT)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_GATS)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDC_STATS)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_ERROR)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_CLIENT_ERROR)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_SERVER_ERROR)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_STORED)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_NOT_STORED)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_EXISTS)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_NOT_FOUND)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_END)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_DELETED)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_TOUCHED)) *matches += 1;
  else if (! MEMCACHED_MATCH(MCDR_STAT)) *matches += 1;

  if (*matches >= MEMCACHED_MIN_MATCH)
    ndpi_int_memcached_add_connection(ndpi_struct, flow);
}

void init_memcached_dissector(
			      struct ndpi_detection_module_struct *ndpi_struct,
			      u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("MEMCACHED",
				      ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MEMCACHED,
				      ndpi_search_memcached,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
