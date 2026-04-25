/*
 * mail_smtp.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MAIL_SMTP

#include "ndpi_api.h"
#include "ndpi_private.h"

/* Bitmask flags for observed SMTP server responses */
#define SMTP_BIT_220		0x0001
#define SMTP_BIT_250		0x0002
#define SMTP_BIT_235		0x0004
#define SMTP_BIT_334		0x0008
#define SMTP_BIT_354		0x0010
/* Bitmask flags for observed SMTP client commands */
#define SMTP_BIT_HELO_EHLO	0x0020
#define SMTP_BIT_MAIL		0x0040
#define SMTP_BIT_RCPT		0x0080
#define SMTP_BIT_AUTH_LOGIN	0x0100
#define SMTP_BIT_STARTTLS	0x0200
#define SMTP_BIT_DATA		0x0400
#define SMTP_BIT_NOOP		0x0800
#define SMTP_BIT_RSET		0x1000
#define SMTP_BIT_TlRM		0x2000
#define SMTP_BIT_AUTH_PLAIN	0x4000

/* #define SMTP_DEBUG 1 */

static void smtpInitExtraPacketProcessing(struct ndpi_flow_struct *flow);

/* **************************************** */

static void smtp_set_detected(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow) {
#ifdef SMTP_DEBUG
  printf("**** %s()\n", __FUNCTION__);
#endif
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_MAIL_SMTP, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* **************************************** */

static void smtp_extract_auth_plain_credentials(struct ndpi_detection_module_struct *ndpi_struct,
                                                struct ndpi_flow_struct *flow,
                                                const u_int8_t *line, u_int16_t line_len) {
  /* Payload format: "AUTH PLAIN <base64>\r\n"
     Skip the 11-byte prefix "AUTH PLAIN " before the encoded credentials. */
  const u_int16_t prefix_len = 11;
  u_int8_t buf[255];
  u_char *decoded;
  size_t decoded_len;
  size_t i;
  unsigned int user_len = 0;

  if(line_len <= prefix_len)
    return;

  ndpi_user_pwd_payload_copy(buf, sizeof(buf), 0,
                             line + prefix_len, line_len - prefix_len);
  decoded = ndpi_base64_decode(buf, strlen((char *)buf), &decoded_len);
  if(!decoded)
    return;

  /* Encoded format: UTF8NUL authcid UTF8NUL passwd — find the NUL after authcid */
  for(i = 1; i < decoded_len; i++) {
    if(decoded[i] == '\0') {
      user_len = i - 1;
      break;
    }
  }

  if(user_len > 0) {
    char msg[64];

    user_len = ndpi_min(user_len, sizeof(flow->l4.tcp.ftp_imap_pop_smtp.username) - 1);
    memcpy(flow->l4.tcp.ftp_imap_pop_smtp.username, decoded + 1, user_len);
    flow->l4.tcp.ftp_imap_pop_smtp.username[user_len] = '\0';

    snprintf(msg, sizeof(msg), "Found username (%s)",
             flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, msg);

    if(1 + user_len + 1 < decoded_len) {
      unsigned int pwd_len = ndpi_min(decoded_len - (1 + user_len + 1),
                                      sizeof(flow->l4.tcp.ftp_imap_pop_smtp.password) - 1);
      memcpy(flow->l4.tcp.ftp_imap_pop_smtp.password, decoded + 1 + user_len + 1, pwd_len);
      flow->l4.tcp.ftp_imap_pop_smtp.password[pwd_len] = '\0';
    }
  }

  ndpi_free(decoded);
}

/* **************************************** */

static void ndpi_search_mail_smtp_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                                      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t a;
  u_int8_t bit_count = 0;

  NDPI_LOG_DBG(ndpi_struct, "search mail_smtp\n");

  if(packet->payload_packet_len <= 2)
    goto smtp_exclude;

  if(ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) != 0x0d0a)
    goto smtp_maybe_early;

  if(packet->parsed_lines >= NDPI_MAX_PARSE_LINES_PER_PACKET)
    goto smtp_exclude;

  NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);

  for(a = 0; a < packet->parsed_lines; a++) {
    const u_int8_t *ptr = packet->line[a].ptr;
    u_int16_t len = packet->line[a].len;

    /* --- Server response codes (3 chars minimum) --- */
    if(len >= 3) {
      if(memcmp(ptr, "220", 3) == 0) {
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_220;

        /* Extract server hostname from the banner "220 hostname ..." */
        if(flow->host_server_name[0] == '\0' && len > 4 && ptr[4] != '(') {
          int i;
          for(i = 5; i < len - 1 && ptr[i] != ' '; i++)
            ;
          if(ptr[i + 1] != '\r' && ptr[i + 1] != '\n') {
            unsigned int hlen = i - 4;
            ndpi_hostname_sni_set(flow, &ptr[4], hlen, NDPI_HOSTNAME_NORM_ALL);
            NDPI_LOG_DBG(ndpi_struct, "SMTP: hostname [%s]\n", flow->host_server_name);
            ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MAIL_SMTP,
                                         flow->host_server_name,
                                         strlen(flow->host_server_name));
            if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
              NDPI_LOG_DBG(ndpi_struct, "SMTP: hostname matched\n");
              smtpInitExtraPacketProcessing(flow);
            }
          }
        }
      } else if(memcmp(ptr, "250", 3) == 0) {
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_250;
      } else if(memcmp(ptr, "235", 3) == 0) {
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_235;
      } else if(memcmp(ptr, "334", 3) == 0) {
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_334;
      } else if(memcmp(ptr, "354", 3) == 0) {
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_354;
      }
    }

    /* --- Client commands (5 chars minimum) --- */
    if(len >= 5) {
      if(ndpi_memcasecmp(ptr, "HELO ", 5) == 0 ||
         ndpi_memcasecmp(ptr, "EHLO ", 5) == 0) {
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_HELO_EHLO;
        flow->l4.tcp.ftp_imap_pop_smtp.auth_found = 0;
      } else if(ndpi_memcasecmp(ptr, "MAIL ", 5) == 0) {
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_MAIL;
        flow->l4.tcp.ftp_imap_pop_smtp.auth_found = 0;
        flow->l4.tcp.ftp_imap_pop_smtp.auth_done = 1;
      } else if(ndpi_memcasecmp(ptr, "RCPT ", 5) == 0) {
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_RCPT;
        flow->l4.tcp.ftp_imap_pop_smtp.auth_found = 0;
        flow->l4.tcp.ftp_imap_pop_smtp.auth_done = 1;
      } else if(ndpi_memcasecmp(ptr, "AUTH ", 5) == 0) {
#ifdef SMTP_DEBUG
        printf("%s() AUTH [%.*s]\n", __FUNCTION__, len, ptr);
#endif
        flow->l4.tcp.ftp_imap_pop_smtp.auth_found = 1;
        if(len >= 6) {
          if(ptr[5] == 'L' || ptr[5] == 'l') {
            flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_AUTH_LOGIN;
          } else if(ptr[5] == 'P' || ptr[5] == 'p') {
            flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_AUTH_PLAIN;
            smtp_extract_auth_plain_credentials(ndpi_struct, flow, ptr, len);
            flow->l4.tcp.ftp_imap_pop_smtp.auth_done = 1;
          }
        }
      } else {
        /* Deferred AUTH LOGIN credential lines arrive without a command prefix */
        if(ptr[3] != ' ' &&
           flow->l4.tcp.ftp_imap_pop_smtp.auth_found &&
           (flow->l4.tcp.smtp_command_bitmask & SMTP_BIT_AUTH_LOGIN)) {
          if(flow->l4.tcp.ftp_imap_pop_smtp.username[0] == '\0') {
            u_int8_t buf[48];
            u_char *decoded;
            size_t decoded_len;
            char msg[64];

            ndpi_user_pwd_payload_copy(buf, sizeof(buf), 0, ptr, len);
#ifdef SMTP_DEBUG
            printf("%s() => [auth: %u] (username) [%s]\n", __FUNCTION__,
                   flow->l4.tcp.ftp_imap_pop_smtp.auth_found, buf);
#endif
            decoded = ndpi_base64_decode((const u_char *)buf,
                                         (size_t)strlen((const char *)buf), &decoded_len);
            if(decoded) {
              size_t ulen = ndpi_min(decoded_len,
                                     sizeof(flow->l4.tcp.ftp_imap_pop_smtp.username) - 1);
              memcpy(flow->l4.tcp.ftp_imap_pop_smtp.username, decoded, ulen);
              flow->l4.tcp.ftp_imap_pop_smtp.username[ulen] = '\0';
              ndpi_free(decoded);
            }
            snprintf(msg, sizeof(msg), "Found SMTP username (%s)",
                     flow->l4.tcp.ftp_imap_pop_smtp.username);
            ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, msg);
          } else if(flow->l4.tcp.ftp_imap_pop_smtp.password[0] == '\0') {
            u_int8_t buf[48];
            u_char *decoded;
            size_t decoded_len;

            ndpi_user_pwd_payload_copy(buf, sizeof(buf), 0, ptr, len);
#ifdef SMTP_DEBUG
            printf("%s() => [auth: %u] (password) [%s]\n", __FUNCTION__,
                   flow->l4.tcp.ftp_imap_pop_smtp.auth_found, buf);
#endif
            decoded = ndpi_base64_decode((const u_char *)buf,
                                         (size_t)strlen((const char *)buf), &decoded_len);
            if(decoded) {
              size_t plen = ndpi_min(decoded_len,
                                     sizeof(flow->l4.tcp.ftp_imap_pop_smtp.password) - 1);
              memcpy(flow->l4.tcp.ftp_imap_pop_smtp.password, decoded, plen);
              flow->l4.tcp.ftp_imap_pop_smtp.password[plen] = '\0';
              ndpi_free(decoded);
            }
            ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, "Found password");
            flow->l4.tcp.ftp_imap_pop_smtp.auth_done = 1;
          } else {
            flow->host_server_name[0] = '\0';
            NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
            return;
          }
        }
      }
    }

    /* --- STARTTLS / X-AnonymousTLS --- */
    if(len >= 8 && ndpi_memcasecmp(ptr, "STARTTLS", 8) == 0) {
      flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_STARTTLS;
      flow->l4.tcp.ftp_imap_pop_smtp.auth_tls = 1;
      flow->l4.tcp.ftp_imap_pop_smtp.auth_done = 0;
    }
    if(len >= 14 && ndpi_memcasecmp(ptr, "X-AnonymousTLS", 14) == 0) {
      flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_STARTTLS;
      flow->l4.tcp.ftp_imap_pop_smtp.auth_tls = 1;
      flow->l4.tcp.ftp_imap_pop_smtp.auth_done = 0;
    }

    /* --- Short 4-letter commands --- */
    if(len >= 4) {
      if(ndpi_memcasecmp(ptr, "DATA", 4) == 0)
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_DATA;
      else if(ndpi_memcasecmp(ptr, "NOOP", 4) == 0)
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_NOOP;
      else if(ndpi_memcasecmp(ptr, "RSET", 4) == 0)
        flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_RSET;
    }
  }

  /* Count distinct tokens observed so far */
  if(flow->l4.tcp.smtp_command_bitmask != 0) {
    u_int16_t mask = flow->l4.tcp.smtp_command_bitmask;
    while(mask) {
      bit_count += mask & 1;
      mask >>= 1;
    }
  }

  NDPI_LOG_DBG2(ndpi_struct, "seen smtp commands and responses: %u\n", bit_count);

  if(bit_count >= 3) {
    NDPI_LOG_INFO(ndpi_struct, "mail smtp identified\n");
#ifdef SMTP_DEBUG
    printf("%s() [bit_count: %u][%s]\n", __FUNCTION__,
           bit_count, flow->l4.tcp.ftp_imap_pop_smtp.password);
#endif
    if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN &&
       flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
      smtp_set_detected(ndpi_struct, flow);
      smtpInitExtraPacketProcessing(flow);
    }
    return;
  }

  if(bit_count >= 1 && flow->packet_counter < 12)
    return;

 smtp_maybe_early:
  /* Tolerate the first few packets even without a proper CRLF terminator */
  if(flow->packet_counter <= 4 &&
     packet->payload_packet_len >= 4 &&
     (ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a ||
      memcmp(packet->payload, "220", 3) == 0 ||
      memcmp(packet->payload, "EHLO", 4) == 0)) {
    NDPI_LOG_DBG2(ndpi_struct, "maybe SMTP, need next packet\n");
    return;
  }

 smtp_exclude:
  if((!flow->extra_packets_func) || (flow->packet_counter > 12))
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

/* **************************************** */

int ndpi_extra_search_mail_smtp_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  int rc;

  if(flow->l4.tcp.smtp_command_bitmask & SMTP_BIT_STARTTLS) {
    /*
     * RFC 3207: after STARTTLS the server replies with:
     *   220  Ready to start TLS
     *   501  Syntax error
     *   454  TLS not available
     */
    if(ndpi_struct->cfg.smtp_opportunistic_tls_enabled &&
       packet->payload_packet_len > 3 && memcmp(packet->payload, "220", 3) == 0) {
      rc = 1;
      if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN &&
         flow->detected_protocol_stack[0] != NDPI_PROTOCOL_MAIL_SMTP) {
        ndpi_set_detected_protocol(ndpi_struct, flow,
                                   flow->detected_protocol_stack[0],
                                   NDPI_PROTOCOL_MAIL_SMTPS, NDPI_CONFIDENCE_DPI);
        flow->protos.tls_quic.subprotocol_detected = 1;
      } else {
        ndpi_set_detected_protocol(ndpi_struct, flow,
                                   NDPI_PROTOCOL_MAIL_SMTPS, NDPI_PROTOCOL_UNKNOWN,
                                   NDPI_CONFIDENCE_DPI);
      }
      NDPI_LOG_DBG(ndpi_struct, "Switching to [%d/%d]\n",
                   flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);
      switch_extra_dissection_to_tls(ndpi_struct, flow);
    } else {
      rc = 0;
    }
  } else {
    ndpi_search_mail_smtp_tcp(ndpi_struct, flow);
    rc = ((flow->l4.tcp.ftp_imap_pop_smtp.password[0] == '\0') &&
          (flow->l4.tcp.ftp_imap_pop_smtp.auth_tls == 1 ||
           flow->l4.tcp.ftp_imap_pop_smtp.auth_done == 0)) ? 1 : 0;
  }

#ifdef SMTP_DEBUG
  printf("**** %s() [rc: %d]\n", __FUNCTION__, rc);
#endif

  return(rc);
}

/* **************************************** */

static void smtpInitExtraPacketProcessing(struct ndpi_flow_struct *flow) {
#ifdef SMTP_DEBUG
  static u_int num = 0;
  printf("**** %s(%u)\n", __FUNCTION__, ++num);
#endif
  flow->max_extra_packets_to_check = 12;
  flow->extra_packets_func = ndpi_extra_search_mail_smtp_tcp;
}

/* **************************************** */

void init_mail_smtp_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("MAIL_SMTP", ndpi_struct,
                          ndpi_search_mail_smtp_tcp,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_MAIL_SMTP);
}
