/*
 * mail_imap.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MAIL_IMAP

#include "ndpi_api.h"
#include "ndpi_private.h"

/* mail_imap_stage is a 3-bit field; cap it at 7 to prevent overflow */
#define SAFE_INC_IMAP_STAGE(flow) \
  do { \
    if((flow)->l4.tcp.mail_imap_stage < 7) \
      (flow)->l4.tcp.mail_imap_stage += 1; \
  } while(0)

/* #define IMAP_DEBUG 1 */

static void imap_set_detected(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow, u_int16_t protocol) {
  ndpi_set_detected_protocol(ndpi_struct, flow, protocol,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* **************************************** */

static void ndpi_search_mail_imap_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                                      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t i = 0;
  u_int16_t space_pos = 0;
  u_int16_t command_start = 0;
  u_int8_t saw_command = 0;

  NDPI_LOG_DBG(ndpi_struct, "search IMAP_IMAP\n");

#ifdef IMAP_DEBUG
  printf("%s() [%.*s]\n", __FUNCTION__, packet->payload_packet_len, packet->payload);
#endif

  if(packet->payload_packet_len < 4)
    goto imap_excluded;
  if(ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) != 0x0d0a)
    goto imap_excluded;

  /* The DONE command carries no tag */
  if(packet->payload_packet_len == 6 && ndpi_memcasecmp(packet->payload, "DONE", 4) == 0) {
    SAFE_INC_IMAP_STAGE(flow);
    saw_command = 1;
    goto imap_check_stage;
  }

  if(flow->l4.tcp.mail_imap_stage < 5) {
    /* Locate the tag: a sequence of alphanumeric / '*' / '.' chars ending at a space */
    while(i < 20 && i < packet->payload_packet_len) {
      if(i > 0 && packet->payload[i] == ' ') {
        space_pos = i;
        break;
      }
      if(!((packet->payload[i] >= 'a' && packet->payload[i] <= 'z') ||
           (packet->payload[i] >= 'A' && packet->payload[i] <= 'Z') ||
           (packet->payload[i] >= '0' && packet->payload[i] <= '9') ||
           packet->payload[i] == '*' ||
           packet->payload[i] == '.'))
        goto imap_excluded;
      i++;
    }
    if(space_pos == 0 || space_pos == (packet->payload_packet_len - 1))
      goto imap_excluded;

    /* Skip an optional message sequence number between tag and command */
    i++;
    if(i < packet->payload_packet_len &&
       packet->payload[i] >= '0' && packet->payload[i] <= '9') {
      while(i < 20 && i < packet->payload_packet_len) {
        if(i > 0 && packet->payload[i] == ' ') {
          space_pos = i;
          break;
        }
        if(!(packet->payload[i] >= '0' && packet->payload[i] <= '9'))
          goto imap_excluded;
        i++;
      }
      if(space_pos == 0 || space_pos == (packet->payload_packet_len - 1))
        goto imap_excluded;
    }
    command_start = space_pos + 1;
  } else {
    command_start = 0;
  }

  /* Match known IMAP commands and server responses */

  if((command_start + 3) < packet->payload_packet_len) {
    if(ndpi_memcasecmp(packet->payload + command_start, "OK ", 3) == 0) {
      SAFE_INC_IMAP_STAGE(flow);
      if(flow->l4.tcp.mail_imap_starttls == 1) {
        NDPI_LOG_DBG2(ndpi_struct, "starttls detected\n");
        imap_set_detected(ndpi_struct, flow, NDPI_PROTOCOL_MAIL_IMAPS);
        if(ndpi_struct->cfg.imap_opportunistic_tls_enabled) {
          NDPI_LOG_DBG(ndpi_struct, "Switching to [%d/%d]\n",
                       flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);
          switch_extra_dissection_to_tls(ndpi_struct, flow);
          return;
        }
      }
      saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "UID", 3) == 0) {
      SAFE_INC_IMAP_STAGE(flow);
      saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "NO ", 3) == 0) {
      SAFE_INC_IMAP_STAGE(flow);
      if(flow->l4.tcp.mail_imap_starttls == 1)
        flow->l4.tcp.mail_imap_starttls = 0;
      saw_command = 1;
    }
  }

  if((command_start + 10) < packet->payload_packet_len) {
    if(ndpi_memcasecmp(packet->payload + command_start, "CAPABILITY", 10) == 0) {
      SAFE_INC_IMAP_STAGE(flow);
      saw_command = 1;
    }
  }

  if((command_start + 8) < packet->payload_packet_len) {
    if(ndpi_memcasecmp(packet->payload + command_start, "STARTTLS", 8) == 0) {
      SAFE_INC_IMAP_STAGE(flow);
      flow->l4.tcp.mail_imap_starttls = 1;
      saw_command = 1;
    }
  }

  if((command_start + 5) < packet->payload_packet_len) {
    if(ndpi_memcasecmp(packet->payload + command_start, "LOGIN", 5) == 0) {
      /* Format: <tag> LOGIN "username" "password"  or  <tag> LOGIN username password */
      char str[256], *user, *saveptr;
      u_int len = ndpi_min(packet->payload_packet_len - (command_start + 5),
                           (int)sizeof(str) - 1);

      ndpi_strlcpy(str, (const char *)packet->payload + command_start + 5, sizeof(str), len);
      user = strtok_r(str, " \"\r\n", &saveptr);
      if(user) {
        char *pwd, buf[64];

        ndpi_snprintf(flow->l4.tcp.ftp_imap_pop_smtp.username,
                      sizeof(flow->l4.tcp.ftp_imap_pop_smtp.username), "%s", user);
        snprintf(buf, sizeof(buf), "Found IMAP username (%s)",
                 flow->l4.tcp.ftp_imap_pop_smtp.username);
        ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, buf);

        pwd = strtok_r(NULL, " \"\r\n", &saveptr);
        if(pwd)
          ndpi_snprintf(flow->l4.tcp.ftp_imap_pop_smtp.password,
                        sizeof(flow->l4.tcp.ftp_imap_pop_smtp.password), "%s", pwd);
      }
      SAFE_INC_IMAP_STAGE(flow);
      saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "FETCH", 5) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "FLAGS", 5) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "CHECK", 5) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "STORE", 5) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    }
  }

  if((command_start + 12) < packet->payload_packet_len) {
    if(ndpi_memcasecmp(packet->payload + command_start, "AUTHENTICATE", 12) == 0) {
      SAFE_INC_IMAP_STAGE(flow);
      /* Auth exchange may span several messages; flag as IMAPS since it is encrypted */
      imap_set_detected(ndpi_struct, flow, NDPI_PROTOCOL_MAIL_IMAPS);
      saw_command = 1;
    }
  }

  if((command_start + 9) < packet->payload_packet_len) {
    if(ndpi_memcasecmp(packet->payload + command_start, "NAMESPACE", 9) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    }
  }

  if((command_start + 4) < packet->payload_packet_len) {
    if(ndpi_memcasecmp(packet->payload + command_start, "LSUB", 4) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "LIST", 4) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "NOOP", 4) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "IDLE", 4) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    }
  }

  if((command_start + 6) < packet->payload_packet_len) {
    if(ndpi_memcasecmp(packet->payload + command_start, "SELECT", 6) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "EXISTS", 6) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    } else if(ndpi_memcasecmp(packet->payload + command_start, "APPEND", 6) == 0) {
      SAFE_INC_IMAP_STAGE(flow); saw_command = 1;
    }
  }

 imap_check_stage:
  if(saw_command) {
    if(flow->l4.tcp.mail_imap_stage == 3 ||
       flow->l4.tcp.mail_imap_stage == 5 ||
       flow->l4.tcp.mail_imap_stage == 7) {
      if(flow->l4.tcp.ftp_imap_pop_smtp.username[0] != '\0' ||
         flow->l4.tcp.mail_imap_stage >= 7) {
        NDPI_LOG_INFO(ndpi_struct, "found MAIL_IMAP\n");
        imap_set_detected(ndpi_struct, flow, NDPI_PROTOCOL_MAIL_IMAP);
      }
      return;
    }
  }

  /* Trailing space may indicate a split command — hold and wait for the next packet */
  if(packet->payload_packet_len > 1 &&
     packet->payload[packet->payload_packet_len - 1] == ' ') {
    NDPI_LOG_DBG2(ndpi_struct,
                  "maybe a split imap command -> need next packet and imap_stage is set to 4.\n");
    flow->l4.tcp.mail_imap_stage = 4;
    return;
  }

 imap_excluded:
  /* Allow a few unrecognised packets if we have already seen at least one IMAP token */
  if(packet->payload_packet_len >= 2 &&
     ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a &&
     flow->packet_counter < 8 &&
     flow->l4.tcp.mail_imap_stage >= 1) {
    NDPI_LOG_DBG2(ndpi_struct,
                  "no imap command or response but packet count < 6 and imap stage >= 1 -> skip\n");
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

/* **************************************** */

void init_mail_imap_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("MAIL_IMAP", ndpi_struct,
                          ndpi_search_mail_imap_tcp,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_MAIL_IMAP);
}
