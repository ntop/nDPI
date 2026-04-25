/*
 * ftp_control.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FTP_CONTROL

#include "ndpi_api.h"
#include "ndpi_private.h"

/* *************************************************************** */

typedef struct {
  const char *cmd;
  u_int8_t    len;
} ftp_cmd_t;

#define FTP_CMD(c) { c, sizeof(c) - 1 }

/* Complete list of standard FTP commands (RFC 959 + extensions) */
static const ftp_cmd_t ftp_commands[] = {
  FTP_CMD("ABOR"), FTP_CMD("ACCT"), FTP_CMD("ADAT"), FTP_CMD("ALLO"),
  FTP_CMD("APPE"), FTP_CMD("CCC"),  FTP_CMD("CDUP"), FTP_CMD("CONF"),
  FTP_CMD("CWD"),  FTP_CMD("DELE"), FTP_CMD("ENC"),  FTP_CMD("EPRT"),
  FTP_CMD("EPSV"), FTP_CMD("FEAT"), FTP_CMD("HELP"), FTP_CMD("HOST"),
  FTP_CMD("LANG"), FTP_CMD("LIST"), FTP_CMD("LPRT"), FTP_CMD("LPSV"),
  FTP_CMD("MDTM"), FTP_CMD("MIC"),  FTP_CMD("MKD"),  FTP_CMD("MLSD"),
  FTP_CMD("MLST"), FTP_CMD("MODE"), FTP_CMD("NLST"), FTP_CMD("NOOP"),
  FTP_CMD("OPTS"), FTP_CMD("PASV"), FTP_CMD("PBSZ"), FTP_CMD("PORT"),
  FTP_CMD("PROT"), FTP_CMD("PWD"),  FTP_CMD("QUIT"), FTP_CMD("REIN"),
  FTP_CMD("REST"), FTP_CMD("RETR"), FTP_CMD("RMD"),  FTP_CMD("RNFR"),
  FTP_CMD("RNTO"), FTP_CMD("SITE"), FTP_CMD("SIZE"), FTP_CMD("SMNT"),
  FTP_CMD("STAT"), FTP_CMD("STOR"), FTP_CMD("STOU"), FTP_CMD("STRU"),
  FTP_CMD("SYST"), FTP_CMD("TYPE"), FTP_CMD("XCUP"), FTP_CMD("XMKD"),
  FTP_CMD("XPWD"), FTP_CMD("XRCP"), FTP_CMD("XRMD"), FTP_CMD("XRSQ"),
  FTP_CMD("XSEM"), FTP_CMD("XSEN")
};

#define FTP_CMD_COUNT (sizeof(ftp_commands) / sizeof(ftp_commands[0]))

/* *************************************************************** */

static inline int ftp_is_delim(u_int8_t c) {
  return (c == ' ' || c == '\r' || c == '\n' || c == '\t');
}

static int ftp_match_command(const u_int8_t *payload, size_t payload_len) {
  size_t i;

  if(payload_len < 3)
    return -1;

  for(i = 0; i < FTP_CMD_COUNT; i++) {
    if(payload_len >= (size_t)ftp_commands[i].len &&
       ndpi_memcasecmp(payload, ftp_commands[i].cmd, ftp_commands[i].len) == 0 &&
       (payload_len == (size_t)ftp_commands[i].len ||
        ftp_is_delim(payload[ftp_commands[i].len])))
      return (int)i;
  }
  return -1;
}

/* *************************************************************** */

static void ftp_control_set_detected(struct ndpi_detection_module_struct *ndpi_struct,
                                     struct ndpi_flow_struct *flow) {
  NDPI_LOG_INFO(ndpi_struct, "found FTP_CONTROL\n");
  flow->host_server_name[0] = '\0';
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_FTP_CONTROL, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* *************************************************************** */

/*
 * Checks whether the payload is USER/PASS/AUTH and extracts credentials.
 * Returns 1 if a recognised auth command was found, 0 otherwise.
 */
static int ftp_handle_auth(struct ndpi_detection_module_struct *ndpi_struct,
                           struct ndpi_flow_struct *flow,
                           const u_int8_t *payload, size_t payload_len) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t port_21 = htons(21);

  if(payload_len < 4)
    return 0;

  if(ndpi_memcasecmp(payload, "USER", 4) == 0 &&
     (payload_len == 4 || ftp_is_delim(payload[4]))) {
    ndpi_user_pwd_payload_copy((u_int8_t *)flow->l4.tcp.ftp_imap_pop_smtp.username,
                               sizeof(flow->l4.tcp.ftp_imap_pop_smtp.username),
                               5, payload, payload_len);
    if(packet->tcp->dest == port_21 || packet->tcp->source == port_21 ||
       flow->detected_protocol_stack[0] == NDPI_PROTOCOL_FTP_CONTROL) {
      char buf[64];
      snprintf(buf, sizeof(buf), "Found FTP username (%s)",
               flow->l4.tcp.ftp_imap_pop_smtp.username);
      ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, buf);
    }
    return 1;
  }

  if(ndpi_memcasecmp(payload, "PASS", 4) == 0 &&
     (payload_len == 4 || ftp_is_delim(payload[4]))) {
    ndpi_user_pwd_payload_copy((u_int8_t *)flow->l4.tcp.ftp_imap_pop_smtp.password,
                               sizeof(flow->l4.tcp.ftp_imap_pop_smtp.password),
                               5, payload, payload_len);
    return 1;
  }

  if(ndpi_memcasecmp(payload, "AUTH", 4) == 0 &&
     (payload_len == 4 || ftp_is_delim(payload[4]))) {
    flow->l4.tcp.ftp_imap_pop_smtp.auth_found = 1;
    return 1;
  }

  return 0;
}

/* *************************************************************** */

/* Parses a 3-digit FTP reply code. Returns the integer code or -1. */
static int ftp_parse_reply_code(const u_int8_t *payload, size_t payload_len) {
  if(payload_len < 3 ||
     !isdigit(payload[0]) || !isdigit(payload[1]) || !isdigit(payload[2]))
    return -1;
  return (payload[0] - '0') * 100 +
         (payload[1] - '0') * 10  +
         (payload[2] - '0');
}

/* *************************************************************** */

static void ndpi_check_ftp_control(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t payload_len = packet->payload_packet_len;
  u_int16_t port_25  = htons(25);
  u_int16_t port_110 = htons(110);
  int code;

  /* SMTP (25) and POP3 (110) use overlapping commands — exclude them. */
  if(packet->tcp->dest == port_25  || packet->tcp->source == port_25  ||
     packet->tcp->dest == port_110 || packet->tcp->source == port_110) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(flow->packet_counter > 8) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(flow->l4.tcp.ftp_control_stage == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "FTP_CONTROL stage 0: \n");

    if(payload_len > 0 &&
       (ftp_handle_auth(ndpi_struct, flow, packet->payload, payload_len) ||
        ftp_match_command(packet->payload, payload_len) >= 0)) {
      NDPI_LOG_DBG2(ndpi_struct,
                    "Possible FTP_CONTROL request detected, we will look further for the response..\n");
      /* Encode the packet direction so we know which direction to expect the reply on. */
      flow->l4.tcp.ftp_control_stage = packet->packet_direction + 1;
    }
    return;
  }

  NDPI_LOG_DBG2(ndpi_struct, "FTP_CONTROL stage %u: \n", flow->l4.tcp.ftp_control_stage);

  /* Same direction as the command — wait for the reply. */
  if((flow->l4.tcp.ftp_control_stage - packet->packet_direction) == 1)
    return;

  /* Opposite direction — look for a valid 3-digit reply code. */
  code = (payload_len > 0) ? ftp_parse_reply_code(packet->payload, payload_len) : -1;

  if(code >= 100 && code < 600) {
    NDPI_LOG_INFO(ndpi_struct, "found FTP_CONTROL\n");

#ifdef FTP_DEBUG
    printf("%s() [user: %s][pwd: %s]\n", __FUNCTION__,
           flow->l4.tcp.ftp_imap_pop_smtp.username,
           flow->l4.tcp.ftp_imap_pop_smtp.password);
#endif

    /* TLS-related response codes (AUTH TLS/SSL) */
    if((code == 234 || code == 334 ||
        code == 631 || code == 632 || code == 633) &&
       flow->l4.tcp.ftp_imap_pop_smtp.auth_found == 1)
      flow->l4.tcp.ftp_imap_pop_smtp.auth_tls = 1;

    /* 4xx/5xx codes indicate auth failure or command rejection */
    if(code >= 400) {
      flow->l4.tcp.ftp_imap_pop_smtp.auth_failed = 1;
      flow->l4.tcp.ftp_imap_pop_smtp.auth_done   = 1;
    }

    /* Upgrade to FTPS if AUTH TLS handshake completed */
    if(flow->l4.tcp.ftp_imap_pop_smtp.auth_tls == 1 &&
       ndpi_struct->cfg.ftp_opportunistic_tls_enabled == 1) {
      flow->host_server_name[0] = '\0';
      ndpi_set_detected_protocol(ndpi_struct, flow,
                                 NDPI_PROTOCOL_FTPS, NDPI_PROTOCOL_UNKNOWN,
                                 NDPI_CONFIDENCE_DPI);
      NDPI_LOG_DBG(ndpi_struct, "Switching to [%d/%d]\n",
                   flow->detected_protocol_stack[0],
                   flow->detected_protocol_stack[1]);
      switch_extra_dissection_to_tls(ndpi_struct, flow);
      return;
    }

    if(flow->l4.tcp.ftp_imap_pop_smtp.password[0] != '\0' ||
       flow->l4.tcp.ftp_imap_pop_smtp.auth_done  != 0) {
      ftp_control_set_detected(ndpi_struct, flow);
    } else {
      /* No credentials captured yet — reset stage and keep looking. */
      flow->l4.tcp.ftp_control_stage = 0;
    }
  } else {
    NDPI_LOG_DBG2(ndpi_struct,
                  "The reply did not seem to belong to FTP_CONTROL, resetting the stage to 0\n");
    flow->l4.tcp.ftp_control_stage = 0;
  }
}

/* *************************************************************** */

static void ndpi_search_ftp_control(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow) {
  NDPI_LOG_DBG(ndpi_struct, "search FTP_CONTROL\n");
  ndpi_check_ftp_control(ndpi_struct, flow);
}

/* *************************************************************** */

void init_ftp_control_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("FTP_CONTROL", ndpi_struct,
                          ndpi_search_ftp_control,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_FTP_CONTROL);
}
