/*
 * dhcp.c
 *
 * Copyright (C) 2016-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DHCP

#include "ndpi_api.h"
#include "ndpi_private.h"

/* freeradius/src/lib/dhcp.c */
#define DHCP_CHADDR_LEN          6
#define DHCP_SNAME_LEN          64
#define DHCP_FILE_LEN          128
#define DHCP_VEND_LEN          308
#define DHCP_OPTION_MAGIC_NUMBER 0x63825363
#define DHCP_MAGIC_LEN           4

PACK_ON
struct dhcp_packet {
  uint8_t  msgType;
  uint8_t  htype;
  uint8_t  hlen;
  uint8_t  hops;
  uint32_t xid;    /* 4   */
  uint16_t secs;   /* 8   */
  uint16_t flags;
  uint32_t ciaddr; /* 12  */
  uint32_t yiaddr; /* 16  */
  uint32_t siaddr; /* 20  */
  uint32_t giaddr; /* 24  */
  uint8_t  chaddr[DHCP_CHADDR_LEN]; /* 28 */
  uint8_t  pad[10];                 /* 34 */
  uint8_t  sname[DHCP_SNAME_LEN];   /* 44 */
  uint8_t  file[DHCP_FILE_LEN];     /* 108 */
  uint8_t  magic[DHCP_MAGIC_LEN];   /* 236 */
  uint8_t  options[DHCP_VEND_LEN];
} PACK_OFF;


static void ndpi_int_dhcp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                         struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DHCP,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* Verify the DHCP magic cookie: 99.130.83.99 (RFC 2131) */
static int is_dhcp_magic(uint8_t *magic) {
  if((magic[0] == 0x63)
     && (magic[1] == 0x82)
     && (magic[2] == 0x53)
     && (magic[3] == 0x63))
    return(1);
  else
    return(0);
}

static void ndpi_search_dhcp_udp(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t msg_type = 0;

  NDPI_LOG_DBG(ndpi_struct, "search DHCP\n");

  /* This detection also works for asymmetric DHCP traffic */

  if(packet->udp) {
    struct dhcp_packet *dhcp = (struct dhcp_packet *)packet->payload;

    /*
     * 244 is the byte offset of options[0] inside struct dhcp_packet.
     * Both client (68) and server (67) ports are accepted in either direction.
     */
    if((packet->payload_packet_len >= 244)
       && (packet->udp->source == htons(67) || packet->udp->source == htons(68))
       && (packet->udp->dest   == htons(67) || packet->udp->dest   == htons(68))
       && is_dhcp_magic(dhcp->magic)) {

      u_int cursor = 0, found_msg_type = 0, opt_offset = 0;

      u_int opts_max = ndpi_min(DHCP_VEND_LEN /* maximum option area in struct dhcp_packet */,
                                packet->payload_packet_len - 240);

      /*
       * Two-pass option scan: the DHCP spec imposes no ordering on options,
       * so we first locate option 53 (message type) to confirm this is DHCP,
       * then continue from that position to collect the other interesting options.
       */

      /* Pass 1: find and validate the DHCP message type */
      while(cursor + 1 /* length byte */ < opts_max) {
        u_int8_t opt_id = dhcp->options[cursor];

        if(opt_id == 0xFF)
          break;

        /* Clamp option length to prevent out-of-bounds reads */
        u_int8_t opt_len = ndpi_min(dhcp->options[cursor + 1] /* len in packet */,
                                    opts_max - (cursor + 2)   /* 1 type + 1 len */);
        if(opt_len == 0)
          break;

        if(opt_id == 53 /* DHCP Message Type */) {
          msg_type = dhcp->options[cursor + 2];

          if(msg_type <= 8) {
            found_msg_type = 1;
            break;
          }
        }

        cursor += opt_len + 2;
      }

      if(!found_msg_type) {
#ifdef DHCP_DEBUG
        NDPI_LOG_DBG2(ndpi_struct, "[DHCP] Invalid message type %d. Not dhcp\n", msg_type);
#endif
        NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
        return;
      }

      /* Valid DHCP packet confirmed */
      NDPI_LOG_INFO(ndpi_struct, "found DHCP\n");
      ndpi_int_dhcp_add_connection(ndpi_struct, flow);

      /*
       * Pass 2: extract options fingerprint, class identifier, and hostname.
       * Resumes at the cursor position left by pass 1 (pointing at option 53).
       */
      while(cursor + 1 /* length byte */ < opts_max) {
        u_int8_t opt_id = dhcp->options[cursor];

        if(opt_id == 0xFF)
          break;

        u_int8_t opt_len = ndpi_min(dhcp->options[cursor + 1] /* len in packet */,
                                    opts_max - (cursor + 2)   /* 1 type + 1 len */);

        if(opt_len == 0 || opt_offset >= sizeof(flow->protos.dhcp.options))
          break;

        int rc;
        rc = ndpi_snprintf((char *)&flow->protos.dhcp.options[opt_offset],
                           sizeof(flow->protos.dhcp.options) - opt_offset,
                           "%s%u", (cursor > 0) ? "," : "", opt_id);

        if(rc > 0) opt_offset += rc;

#ifdef DHCP_DEBUG
        NDPI_LOG_DBG2(ndpi_struct, "[DHCP] Id=%d [len=%d]\n", opt_id, opt_len);
#endif

        if(opt_id == 55 /* Parameter Request List / Fingerprint */) {
          u_int idx, fing_offset = 0;

          for(idx = 0; idx < opt_len && fing_offset < sizeof(flow->protos.dhcp.fingerprint) - 2; idx++) {
            rc = ndpi_snprintf((char *)&flow->protos.dhcp.fingerprint[fing_offset],
                               sizeof(flow->protos.dhcp.fingerprint) - fing_offset,
                               "%s%u", (idx > 0) ? "," : "",
                               (unsigned int)dhcp->options[cursor + 2 + idx] & 0xFF);

            if(rc < 0) break; else fing_offset += rc;
          }

          flow->protos.dhcp.fingerprint[sizeof(flow->protos.dhcp.fingerprint) - 1] = '\0';

        } else if(opt_id == 60 /* Class Identifier */) {
          char *name = (char *)&dhcp->options[cursor + 2];
          int copy_len;

          copy_len = ndpi_min(opt_len, sizeof(flow->protos.dhcp.class_ident) - 1);
          strncpy((char *)flow->protos.dhcp.class_ident, name, copy_len);
          flow->protos.dhcp.class_ident[copy_len] = '\0';

        } else if(opt_id == 12 /* Host Name */) {
          u_int8_t *name = &dhcp->options[cursor + 2];

#ifdef DHCP_DEBUG
          NDPI_LOG_DBG2(ndpi_struct, "[DHCP] '%.*s'\n", name, opt_len);
#endif
          ndpi_hostname_sni_set(flow, name, opt_len, NDPI_HOSTNAME_NORM_ALL);
        }

        cursor += opt_len + 2;
      }

    } else
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  }
}


void init_dhcp_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("DHCP", ndpi_struct,
                          ndpi_search_dhcp_udp,
                          NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
                          1, NDPI_PROTOCOL_DHCP);
}
