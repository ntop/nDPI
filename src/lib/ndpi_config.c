/*
 * ndpi_config.c
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

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <stddef.h>

#ifdef __APPLE__
#include <netinet/ip.h>
#endif

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_private.h"
#include "ahocorasick.h"

#ifndef WIN32
#include <unistd.h>
#include <dirent.h>
#include <netdb.h>
#else
#include "third_party/include/windows/dirent.h"
#endif

typedef ndpi_cfg_error (*cfg_set)(struct ndpi_detection_module_struct *ndpi_str,
                                  void *_variable, const char *value,
                                  const char *min_value, const char *max_value,
                                  const char *proto, const char *param);
typedef char *(*cfg_get)(struct ndpi_detection_module_struct *ndpi_str, void *_variable, const char *proto, char *buf, int buf_len);


static ndpi_cfg_error _set_param_enable_disable(struct ndpi_detection_module_struct *ndpi_str,
						void *_variable, const char *value,
						const char *min_value, const char *max_value,
						const char *proto, const char *param);
static int clbk_only_with_global_ctx(struct ndpi_detection_module_struct *ndpi_str,
				     void *_variable, const char *proto,
				     const char *param);
static ndpi_cfg_error _set_param_int(struct ndpi_detection_module_struct *ndpi_str,
				     void *_variable, const char *value,
				     const char *min_value, const char *max_value,
				     const char *proto, const char *param);
static char *_get_param_int(struct ndpi_detection_module_struct *ndpi_str,
			    void *_variable, const char *proto, char *buf, int buf_len);
static char *_get_param_string(struct ndpi_detection_module_struct *ndpi_str,
			       void *_variable, const char *proto, char *buf, int buf_len);
static ndpi_cfg_error _set_param_filename(struct ndpi_detection_module_struct *ndpi_str,
					  void *_variable, const char *value,
					  const char *min_value, const char *max_value,
					  const char *proto, const char *param);
static ndpi_cfg_error _set_param_filename_config(struct ndpi_detection_module_struct *ndpi_str,
						 void *_variable, const char *value,
						 const char *min_value, const char *max_value,
						 const char *proto, const char *param);
static u_int16_t __get_proto_id(const struct ndpi_detection_module_struct *ndpi_str, const char *proto_name_or_id);
static ndpi_risk_enum __get_flowrisk_id(const char *flowrisk_name_or_id);
static char *_get_param_protocol_enable_disable(struct ndpi_detection_module_struct *ndpi_str,
						void *_variable, const char *proto,
						char *buf, int buf_len);
static ndpi_cfg_error _set_param_protocol_enable_disable(struct ndpi_detection_module_struct *ndpi_str,
							 void *_variable, const char *value,
							 const char *min_value, const char *max_value,
							 const char *proto, const char *param);
static char *_get_param_flowrisk_enable_disable(struct ndpi_detection_module_struct *ndpi_str,
						void *_variable, const char *proto,
						char *buf, int buf_len);
static ndpi_cfg_error _set_param_flowrisk_enable_disable(struct ndpi_detection_module_struct *ndpi_str,
							 void *_variable, const char *value,
							 const char *min_value, const char *max_value,
							 const char *proto, const char *_param);


/* ****************************************** */

static const struct cfg_op {
  enum cfg_param_type type;
  cfg_set fn_set;
  cfg_get fn_get;
} cfg_ops[] = {
  { CFG_PARAM_ENABLE_DISABLE,          _set_param_enable_disable,          _get_param_int },
  { CFG_PARAM_INT,                     _set_param_int,                     _get_param_int },
  { CFG_PARAM_PROTOCOL_ENABLE_DISABLE, _set_param_protocol_enable_disable, _get_param_protocol_enable_disable },
  { CFG_PARAM_FILENAME_CONFIG,         _set_param_filename_config,         _get_param_string },
  { CFG_PARAM_FLOWRISK_ENABLE_DISABLE, _set_param_flowrisk_enable_disable, _get_param_flowrisk_enable_disable },
};

#define __OFF(a)	offsetof(struct ndpi_detection_module_config_struct, a)

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static
#endif
const struct cfg_param cfg_params[] = {
  /* Per-protocol parameters */

  { "http",          "metadata.req.content_type",               "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(http_request_content_type_enabled), NULL },
  { "http",          "metadata.req.referer",                    "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(http_referer_enabled), NULL },
  { "http",          "metadata.req.host",                       "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(http_host_enabled), NULL },
  { "http",          "metadata.req.username",                   "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(http_username_enabled), NULL },
  { "http",          "metadata.req.password",                   "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(http_password_enabled), NULL },
  { "http",          "metadata.resp.content_type",              "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(http_resp_content_type_enabled), NULL },
  { "http",          "metadata.resp.server",                    "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(http_resp_server_enabled), NULL },

  { "tls",           "certificate_expiration_threshold",        "30", "0", "365", CFG_PARAM_INT, __OFF(tls_certificate_expire_in_x_days), NULL },
  { "tls",           "application_blocks_tracking",             "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_app_blocks_tracking_enabled), NULL },
  { "tls",           "dpi.heuristics",                          "0x00", "0", "0x07", CFG_PARAM_INT, __OFF(tls_heuristics), NULL },
  { "tls",           "dpi.heuristics.max_packets_extra_dissection", "25", "0", "255", CFG_PARAM_INT, __OFF(tls_heuristics_max_packets), NULL },
  { "tls",           "metadata.sha1_fingerprint",               "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_sha1_fingerprint_enabled), NULL },
  { "tls",           "metadata.versions_supported",             "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_versions_supported_enabled), NULL },
  { "tls",           "metadata.alpn_negotiated",                "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_alpn_negotiated_enabled), NULL },
  { "tls",           "metadata.cipher",                         "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_cipher_enabled), NULL },
  { "tls",           "metadata.cert_server_names",              "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_cert_server_names_enabled), NULL },
  { "tls",           "metadata.cert_validity",                  "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_cert_validity_enabled), NULL },
  { "tls",           "metadata.cert_issuer",                    "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_cert_issuer_enabled), NULL },
  { "tls",           "metadata.cert_subject",                   "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_cert_subject_enabled), NULL },
  { "tls",           "metadata.browser",                        "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_browser_enabled), NULL },
  { "tls",           "metadata.ja3s_fingerprint",               "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_ja3s_fingerprint_enabled), NULL },
  { "tls",           "metadata.ja4c_fingerprint",               "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_ja4c_fingerprint_enabled), NULL },
  { "tls",           "metadata.ja4r_fingerprint",               "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_ja4r_fingerprint_enabled), NULL },
  { "tls",           "metadata.ja_data",                        "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_ja_data_enabled), NULL },
  { "tls",           "metadata.ja_ignore_ephemeral_tls_extn",   "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_ja_ignore_ephemeral_extensions), NULL },
  { "tls",           "metadata.ndpifp_ignore_sni_tls_extn",     "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_ndpifp_ignore_sni_extension), NULL },
  { "tls",           "subclassification",                       "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_subclassification_enabled), NULL },
  { "tls",           "max_num_blocks_to_analyze",               "0", "0", "256", CFG_PARAM_INT, __OFF(tls_max_num_blocks_to_analyze), NULL },  /* 0 = tls blocks are not analyzed */
  { "tls",           "tls_blocks_show_timing",                  "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_blocks_show_timing), NULL },
  { "quic",          "subclassification",                       "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(quic_subclassification_enabled), NULL },

  { "smtp",          "tls_dissection",                          "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(smtp_opportunistic_tls_enabled), NULL },

  { "imap",          "tls_dissection",                          "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(imap_opportunistic_tls_enabled), NULL },

  { "pop",           "tls_dissection",                          "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(pop_opportunistic_tls_enabled), NULL },

  { "ftp",           "tls_dissection",                          "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(ftp_opportunistic_tls_enabled), NULL },

  { "sip",           "metadata.attribute.from",                 "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(sip_attribute_from_enabled), NULL },
  { "sip",           "metadata.attribute.from_imsi",            "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(sip_attribute_from_imsi_enabled), NULL },
  { "sip",           "metadata.attribute.to",                   "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(sip_attribute_to_enabled), NULL },
  { "sip",           "metadata.attribute.to_imsi",              "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(sip_attribute_to_imsi_enabled), NULL },

  { "ssh",           "metadata.hassh_fingerprint",              "enable",  NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(ssh_hassh_fingerprint_enabled), NULL },
  { "ssh",           "metadata.ssh_data",                       "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(ssh_hassh_data_enabled), NULL },

  { "stun",          "tls_dissection",                          "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(stun_opportunistic_tls_enabled), NULL },
  { "stun",          "max_packets_extra_dissection",            "6", "0", "255", CFG_PARAM_INT, __OFF(stun_max_packets_extra_dissection), NULL },
  { "stun",          "metadata.attribute.mapped_address",       "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(stun_mapped_address_enabled), NULL },
  { "stun",          "metadata.attribute.response_origin",      "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(stun_response_origin_enabled), NULL },
  { "stun",          "metadata.attribute.other_address",        "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(stun_other_address_enabled), NULL },
  { "stun",          "metadata.attribute.relayed_address",      "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(stun_relayed_address_enabled), NULL },
  { "stun",          "metadata.attribute.peer_address",         "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(stun_peer_address_enabled), NULL },

  { "bittorrent",    "metadata.hash",                           "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(bittorrent_hash_enabled), NULL },

  { "ssdp",          "metadata",                                "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(ssdp_metadata_enabled), NULL },

  { "ntp",           "metadata",                                "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(ntp_metadata_enabled), NULL },

  { "dns",           "subclassification",                       "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(dns_subclassification_enabled), NULL },
  { "dns",           "process_response",                        "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(dns_parse_response_enabled), NULL },

  { "http",          "process_response",                        "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(http_parse_response_enabled), NULL },
  { "http",          "subclassification",                       "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(http_subclassification_enabled), NULL },

  { "ookla",         "dpi.aggressiveness",                      "0x01", "0", "1", CFG_PARAM_INT, __OFF(ookla_aggressiveness), NULL },

  { "zoom",          "max_packets_extra_dissection",            "4", "0", "255", CFG_PARAM_INT, __OFF(zoom_max_packets_extra_dissection), NULL },

  { "rtp",           "search_for_stun",                         "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(rtp_search_for_stun), NULL },
  { "rtp",           "max_packets_extra_dissection",            "32", "0", "255", CFG_PARAM_INT, __OFF(rtp_max_packets_extra_dissection), NULL },

  { "openvpn",       "dpi.heuristics",                          "0x00", "0", "0x01", CFG_PARAM_INT, __OFF(openvpn_heuristics), NULL },
  { "openvpn",       "dpi.heuristics.num_messages",             "10", "0", "255", CFG_PARAM_INT, __OFF(openvpn_heuristics_num_msgs), NULL },
  { "openvpn",       "subclassification_by_ip",                 "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(openvpn_subclassification_by_ip), NULL },

  { "wireguard",     "subclassification_by_ip",                 "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(wireguard_subclassification_by_ip), NULL },

  { "$PROTO_NAME_OR_ID", "log",                                 "disable", NULL, NULL, CFG_PARAM_PROTOCOL_ENABLE_DISABLE, __OFF(debug_bitmask), NULL },
  { "$PROTO_NAME_OR_ID", "ip_list.load",                        "1", NULL, NULL, CFG_PARAM_PROTOCOL_ENABLE_DISABLE, __OFF(ip_list_bitmask), NULL },
  { "$PROTO_NAME_OR_ID", "monitoring",                          "disable", NULL, NULL, CFG_PARAM_PROTOCOL_ENABLE_DISABLE, __OFF(monitoring), NULL },
  { "$PROTO_NAME_OR_ID", "enable",                              "1", NULL, NULL, CFG_PARAM_PROTOCOL_ENABLE_DISABLE, __OFF(detection_bitmask), NULL },

  /* Global parameters */

  { NULL,            "packets_limit_per_flow",                  "32", "0", "255", CFG_PARAM_INT, __OFF(max_packets_to_process), NULL },
  { NULL,            "flow.track_payload",                      "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(track_payload_enabled), NULL },
  { NULL,            "flow.use_client_ip_in_guess",             "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(use_client_ip_in_guess), NULL},
  { NULL,            "flow.use_client_port_in_guess",           "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(use_client_port_in_guess), NULL},
  { NULL,            "tcp_ack_payload_heuristic",               "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tcp_ack_paylod_heuristic), NULL },
  { NULL,            "fully_encrypted_heuristic",               "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(fully_encrypted_heuristic), NULL },
  { NULL,            "libgcrypt.init",                          "1", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(libgcrypt_init), NULL },
  { NULL,            "dpi.guess_on_giveup",                     "0x3", "0", "3", CFG_PARAM_INT, __OFF(guess_on_giveup), NULL },
  { NULL,            "dpi.guess_ip_before_port",                "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(guess_ip_before_port), NULL},
  { NULL,            "dpi.compute_entropy",                     "1", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(compute_entropy), NULL },
  { NULL,            "dpi.address_cache_size",                  "0", "0", "16777215", CFG_PARAM_INT, __OFF(address_cache_size), NULL },
  { NULL,            "fpc",                                     "1", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(fpc_enabled), NULL },
  { NULL,            "hostname_dns_check",                      "0", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(hostname_dns_check_enabled), NULL },

  { NULL,            "metadata.tcp_fingerprint",                "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tcp_fingerprint_enabled), NULL },
  { NULL,            "metadata.tcp_fingerprint_raw",            "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tcp_fingerprint_raw_enabled), NULL },
  { NULL,            "metadata.tcp_fingerprint_format",         "0", "0" /* min */, "1" /* max */, CFG_PARAM_INT, __OFF(tcp_fingerprint_format), NULL },

  { NULL,            "metadata.ndpi_server_fingerprint",        "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(ndpi_server_fingerprint_enabled), NULL },
  { NULL,            "metadata.ndpi_fingerprint",               "enable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(ndpi_fingerprint_enabled), NULL },
  { NULL,            "metadata.ndpi_fingerprint_format",         "0", "0" /* client-only */, "1" /* client+server only */, CFG_PARAM_INT, __OFF(ndpi_fingerprint_format), NULL },
  { NULL,            "metadata.ndpi_fingerprint_ignore_tcp_fp", "disable", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(tls_ndpifp_ignore_tcp_fingerprint), NULL },
  { NULL,            "flow_risk_lists.load",                    "1", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(flow_risk_lists_enabled), NULL },

  { NULL,            "flow_risk.$FLOWRISK_NAME_OR_ID",          "enable", NULL, NULL, CFG_PARAM_FLOWRISK_ENABLE_DISABLE, __OFF(flowrisk_bitmask), NULL },
  { NULL,            "flow_risk.$FLOWRISK_NAME_OR_ID.info",     "enable", NULL, NULL, CFG_PARAM_FLOWRISK_ENABLE_DISABLE, __OFF(flowrisk_info_bitmask), NULL },

  { NULL,            "flow_risk.anonymous_subscriber.list.icloudprivaterelay.load", "1", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(risk_anonymous_subscriber_list_icloudprivaterelay_enabled), NULL },
  { NULL,            "flow_risk.anonymous_subscriber.list.tor.load",                "1", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(risk_anonymous_subscriber_list_tor_exit_nodes_enabled), NULL },
  { NULL,            "flow_risk.crawler_bot.list.load",                             "1", NULL, NULL, CFG_PARAM_ENABLE_DISABLE, __OFF(risk_crawler_bot_list_enabled), NULL },

  { NULL,            "filename.config",                         NULL, NULL, NULL, CFG_PARAM_FILENAME_CONFIG, __OFF(filename_config), NULL },

  { NULL,            "log.level",                               "0", "0", "3", CFG_PARAM_INT, __OFF(log_level), NULL },

  /* LRU caches */

  { NULL,            "lru.ookla.size",                          "1024", "0", "16777215", CFG_PARAM_INT, __OFF(ookla_cache_num_entries), NULL },
  { NULL,            "lru.ookla.ttl",                           "120", "0", "16777215", CFG_PARAM_INT, __OFF(ookla_cache_ttl), NULL },
  { NULL,            "lru.ookla.scope",                         "0", "0", "1", CFG_PARAM_INT, __OFF(ookla_cache_scope), clbk_only_with_global_ctx },

  { NULL,            "lru.bittorrent.size",                     "32768", "0", "16777215", CFG_PARAM_INT, __OFF(bittorrent_cache_num_entries), NULL },
  { NULL,            "lru.bittorrent.ttl",                      "300", "0", "16777215", CFG_PARAM_INT, __OFF(bittorrent_cache_ttl), NULL },
  { NULL,            "lru.bittorrent.scope",                    "0", "0", "1", CFG_PARAM_INT, __OFF(bittorrent_cache_scope), clbk_only_with_global_ctx },

  { NULL,            "lru.stun.size",                           "1024", "0", "16777215", CFG_PARAM_INT, __OFF(stun_cache_num_entries), NULL },
  { NULL,            "lru.stun.ttl",                            "300", "0", "16777215", CFG_PARAM_INT, __OFF(stun_cache_ttl), NULL },
  { NULL,            "lru.stun.scope",                          "0", "0", "1", CFG_PARAM_INT, __OFF(stun_cache_scope), clbk_only_with_global_ctx },

  { NULL,            "lru.tls_cert.size",                       "1024", "0", "16777215", CFG_PARAM_INT, __OFF(tls_cert_cache_num_entries), NULL },
  { NULL,            "lru.tls_cert.ttl",                        "300", "0", "16777215", CFG_PARAM_INT, __OFF(tls_cert_cache_ttl), NULL },
  { NULL,            "lru.tls_cert.scope",                      "0", "0", "1", CFG_PARAM_INT, __OFF(tls_cert_cache_scope), clbk_only_with_global_ctx },

  { NULL,            "lru.mining.size",                         "1024", "0", "16777215", CFG_PARAM_INT, __OFF(mining_cache_num_entries), NULL },
  { NULL,            "lru.mining.ttl",                          "300", "0", "16777215", CFG_PARAM_INT, __OFF(mining_cache_ttl), NULL },
  { NULL,            "lru.mining.scope",                        "0", "0", "1", CFG_PARAM_INT, __OFF(mining_cache_scope), clbk_only_with_global_ctx },

  { NULL,            "lru.msteams.size",                        "1024", "0", "16777215", CFG_PARAM_INT, __OFF(msteams_cache_num_entries), NULL },
  { NULL,            "lru.msteams.ttl",                         "60", "0", "16777215", CFG_PARAM_INT, __OFF(msteams_cache_ttl), NULL },
  { NULL,            "lru.msteams.scope",                       "0", "0", "1", CFG_PARAM_INT, __OFF(msteams_cache_scope), clbk_only_with_global_ctx },

  { NULL,            "lru.fpc_dns.size",                        "1024", "0", "16777215", CFG_PARAM_INT, __OFF(fpc_dns_cache_num_entries), NULL },
  { NULL,            "lru.fpc_dns.ttl",                         "60", "0", "16777215", CFG_PARAM_INT, __OFF(fpc_dns_cache_ttl), NULL },
  { NULL,            "lru.fpc_dns.scope",                       "0", "0", "1", CFG_PARAM_INT, __OFF(fpc_dns_cache_scope), clbk_only_with_global_ctx },

  { NULL,            "lru.signal.size",                         "32768", "0", "16777215", CFG_PARAM_INT, __OFF(signal_cache_num_entries), NULL },
  { NULL,            "lru.signal.ttl",                          "300", "0", "16777215", CFG_PARAM_INT, __OFF(signal_cache_ttl), NULL },
  { NULL,            "lru.signal.scope",                        "0", "0", "1", CFG_PARAM_INT, __OFF(signal_cache_scope), clbk_only_with_global_ctx },

  { NULL, NULL, NULL, NULL, NULL, 0, -1, NULL },
};

#undef __OFF

/* ****************************************** */

int ndpi_set_default_config(struct ndpi_detection_module_config_struct *cfg,
			    u_int16_t max_internal_proto)
{
  const struct cfg_param *c;

  if(ndpi_bitmask_alloc(&cfg->detection_bitmask, max_internal_proto) != 0 ||
     ndpi_bitmask_alloc(&cfg->debug_bitmask, max_internal_proto) != 0 ||
     ndpi_bitmask_alloc(&cfg->ip_list_bitmask, max_internal_proto) != 0 ||
     ndpi_bitmask_alloc(&cfg->monitoring, max_internal_proto) != 0 ||
     ndpi_bitmask_alloc(&cfg->flowrisk_bitmask, NDPI_MAX_RISK) != 0 ||
     ndpi_bitmask_alloc(&cfg->flowrisk_info_bitmask, NDPI_MAX_RISK) != 0)
    return -1;

  for(c = &cfg_params[0]; c && c->param; c++) {
    cfg_ops[c->type].fn_set(NULL, (void *)((char *)cfg + c->offset),
                            c->default_value, c->min_value, c->max_value, c->proto, c->param);
  }
  return 0;
}

/* ****************************************** */

ndpi_cfg_error ndpi_set_config(struct ndpi_detection_module_struct *ndpi_str,
		               const char *proto, const char *param, const char *value)
{
  const struct cfg_param *c;
  ndpi_cfg_error rc;
  int ret;

  if(!ndpi_str || !param || !value)
    return NDPI_CFG_INVALID_CONTEXT;
  if(ndpi_str->finalized)
    return NDPI_CFG_CONTEXT_ALREADY_INITIALIZED;

  NDPI_LOG_DBG(ndpi_str, "Set [%s][%s][%s]\n", proto, param, value);

  if(proto && (strcmp(proto, "NULL") == 0))
    proto = NULL;

  for(c = &cfg_params[0]; c && c->param; c++) {
    if((((proto == NULL && c->proto == NULL) ||
	 (proto && c->proto && strcmp(proto, c->proto) == 0)) &&
        strcmp(param, c->param) == 0) ||
       (proto && c->proto &&
	strcmp(c->proto, "$PROTO_NAME_OR_ID") == 0 &&
	strcmp(param, c->param) == 0) ||
       (proto == NULL && c->proto == NULL &&
	strncmp(c->param, "flow_risk.$FLOWRISK_NAME_OR_ID", 30) == 0 &&
	strncmp(param, "flow_risk.", 10) == 0 &&
	!ndpi_str_endswith(param, ".info") &&
	!ndpi_str_endswith(param, ".load")) ||
       (proto == NULL && c->proto == NULL &&
	strncmp(c->param, "flow_risk.$FLOWRISK_NAME_OR_ID.info", 35) == 0 &&
	strncmp(param, "flow_risk.", 10) == 0 &&
	ndpi_str_endswith(param, ".info"))) {

      rc = cfg_ops[c->type].fn_set(ndpi_str, (void *)((char *)&ndpi_str->cfg + c->offset),
                                   value, c->min_value, c->max_value, proto, param);
      if(rc == NDPI_CFG_OK && c->fn_callback) {
        ret = c->fn_callback(ndpi_str, (void *)((char *)&ndpi_str->cfg + c->offset),
                             proto, param);
        if(ret < 0)
          rc = NDPI_CFG_CALLBACK_ERROR;
        else
          rc = ret;
      }
      return rc;
    }
  }
  return NDPI_CFG_NOT_FOUND;
}

/* ****************************************** */

ndpi_cfg_error ndpi_set_config_u64(struct ndpi_detection_module_struct *ndpi_str,
                                   const char *proto, const char *param, uint64_t value)
{
  char value_str[21];
  int value_len;

  value_len = ndpi_snprintf(value_str, sizeof(value_str), "%llu", (unsigned long long int)value);
  if (value_len <= 0 || value_len >= (int)sizeof(value_str))
    {
      return NDPI_CFG_INVALID_PARAM;
    }

  return ndpi_set_config(ndpi_str, proto, param, value_str);
}

/* ****************************************** */

char *ndpi_get_config(struct ndpi_detection_module_struct *ndpi_str,
		      const char *proto, const char *param, char *buf, int buf_len)
{
  const struct cfg_param *c;

  if(!ndpi_str || !param || !buf || buf_len <= 0)
    return NULL;

  NDPI_LOG_DBG(ndpi_str, "Get [%s][%s]\n", proto, param);

  for(c = &cfg_params[0]; c && c->param; c++) {
    if((((proto == NULL && c->proto == NULL) ||
	 (proto && c->proto && strcmp(proto, c->proto) == 0)) &&
        strcmp(param, c->param) == 0) ||
       (proto && c->proto &&
	strcmp(c->proto, "$PROTO_NAME_OR_ID") == 0 &&
	strcmp(param, c->param) == 0) ||
       (proto == NULL && c->proto == NULL &&
	strcmp(c->param, "flow_risk.$FLOWRISK_NAME_OR_ID") == 0 &&
	strcmp(param, c->param) == 0)) {

      return cfg_ops[c->type].fn_get(ndpi_str, (void *)((char *)&ndpi_str->cfg + c->offset), proto, buf, buf_len);
    }
  }
  return NULL;
}

/* ****************************************** */

char *ndpi_dump_config(struct ndpi_detection_module_struct *ndpi_str, FILE *fd) {
  const struct cfg_param *c;
  char buf[64];

  if(!ndpi_str || !fd)
    return NULL;

  fprintf(fd, " Protocol (empty/NULL for global knobs), parameter, value, [default value], [min value, max_value]\n");

  /* TODO */
  for(c = &cfg_params[0]; c && c->param; c++) {
    switch(c->type) {
    case CFG_PARAM_ENABLE_DISABLE:
    case CFG_PARAM_INT:
      fprintf(fd, " *) %s %s: %s [%s]",
              c->proto ? c->proto : "NULL",
              c->param,
              _get_param_int(ndpi_str, (void *)((char *)&ndpi_str->cfg + c->offset), c->proto, buf, sizeof(buf)),
	      c->default_value);
      if(c->min_value && c->max_value)
        fprintf(fd, " [%s-%s]", c->min_value, c->max_value);
      fprintf(fd, "\n");
      break;
    case CFG_PARAM_FILENAME_CONFIG:
      fprintf(fd, " *) %s %s: %s [%s]",
              c->proto ? c->proto : "NULL",
              c->param,
	      _get_param_string(ndpi_str, (void *)((char *)&ndpi_str->cfg + c->offset), c->proto, buf, sizeof(buf)),
	      c->default_value);
      fprintf(fd, "\n");
      break;
      /* TODO */
    case CFG_PARAM_PROTOCOL_ENABLE_DISABLE:
      fprintf(fd, " *) %s %s: %s [all %s]",
              c->proto,
              c->param,
              /* TODO */ _get_param_protocol_enable_disable(ndpi_str, (void *)((char *)&ndpi_str->cfg + c->offset), "any", buf, sizeof(buf)),
	      c->default_value);
      fprintf(fd, "\n");
      break;
      /* TODO */
    case CFG_PARAM_FLOWRISK_ENABLE_DISABLE:
      fprintf(fd, " *) %s %s: %s [all %s]",
	      c->proto ? c->proto : "NULL",
	      c->param,
	      /* TODO */ _get_param_flowrisk_enable_disable(ndpi_str, (void *)((char *)&ndpi_str->cfg + c->offset), "any", buf, sizeof(buf)),
	      c->default_value);
      fprintf(fd, "\n");
      break;
    }
  }

  return NULL;
}

/* ****************************************** */

static ndpi_cfg_error _set_param_enable_disable(struct ndpi_detection_module_struct *ndpi_str,
                                                void *_variable, const char *value,
                                                const char *min_value, const char *max_value,
                                                const char *proto, const char *param) {
  int *variable = (int *)_variable;

  (void)ndpi_str;
  (void)min_value;
  (void)max_value;
  (void)proto;
  (void)param;

  if(strcmp(value, "1") == 0 ||
     strcmp(value, "enable") == 0) {
    *variable = 1;
    return NDPI_CFG_OK;
  }

  if(strcmp(value, "0") == 0 ||
     strcmp(value, "disable") == 0) {
    *variable = 0;
    return NDPI_CFG_OK;
  }

  return NDPI_CFG_INVALID_PARAM;
}

/* ****************************************** */

static int clbk_only_with_global_ctx(struct ndpi_detection_module_struct *ndpi_str,
                                     void *_variable, const char *proto,
                                     const char *param)
{
  int *variable = (int *)_variable;

  (void)proto;
  (void)param;

  /* Integer set > 0 only if there is a global context */
  if(*variable > 0 && !ndpi_str->g_ctx) {
    *variable = 0;
    return -1;
  }
  return 0;
}

/* ****************************************** */

static ndpi_cfg_error _set_param_int(struct ndpi_detection_module_struct *ndpi_str,
                                     void *_variable, const char *value,
                                     const char *min_value, const char *max_value,
                                     const char *proto, const char *param) {
  int *variable = (int *)_variable;
  const char *errstrp;
  long val;

  (void)ndpi_str;
  (void)proto;
  (void)param;

  val = ndpi_strtonum(value, LONG_MIN, LONG_MAX, &errstrp, 0);
  if(errstrp) {
    return NDPI_CFG_INVALID_PARAM;
  }

  /* Min and max values are set in the code, so we can convert them
     to integers without too many checks...*/
  if(min_value && max_value &&
     (val < strtol(min_value, NULL, 0) || val > strtol(max_value, NULL, 0)))
    return NDPI_CFG_INVALID_PARAM;

  *variable = val;

  return NDPI_CFG_OK;
}

/* ****************************************** */

static char *_get_param_int(struct ndpi_detection_module_struct *ndpi_str,
                            void *_variable, const char *proto, char *buf, int buf_len) {
  int *variable = (int *)_variable;

  (void)ndpi_str;
  (void)proto;

  snprintf(buf, buf_len, "%d", *variable);
  buf[buf_len - 1] = '\0';
  return buf;
}

/* ****************************************** */

static char *_get_param_string(struct ndpi_detection_module_struct *ndpi_str,
                               void *_variable, const char *proto, char *buf, int buf_len) {
  char *variable = (char *)_variable;

  (void)ndpi_str;
  (void)proto;

  snprintf(buf, buf_len, "%s", variable);
  buf[buf_len - 1] = '\0';
  return buf;
}

/* ****************************************** */

static ndpi_cfg_error _set_param_filename(struct ndpi_detection_module_struct *ndpi_str,
                                          void *_variable, const char *value,
                                          const char *min_value, const char *max_value,
                                          const char *proto, const char *param) {
  char *variable = (char *)_variable;

  (void)ndpi_str;
  (void)min_value;
  (void)max_value;
  (void)proto;
  (void)param;

  if(value == NULL) { /* Valid value */
    variable[0] = '\0';
    return NDPI_CFG_OK;
  }

  if(access(value, F_OK) != 0)
    return NDPI_CFG_INVALID_PARAM;

  strncpy(variable, value, CFG_MAX_LEN);
  return NDPI_CFG_OK;
}

/* ****************************************** */

static ndpi_cfg_error _set_param_filename_config(struct ndpi_detection_module_struct *ndpi_str,
                                                 void *_variable, const char *value,
                                                 const char *min_value, const char *max_value,
                                                 const char *proto, const char *param) {
  int rc;
  FILE *fd;

  rc = _set_param_filename(ndpi_str, _variable, value, min_value, max_value, proto, param);
  if(rc != 0 || value == NULL || ndpi_str == NULL)
    return rc;

  fd = fopen(value, "r");

  if(fd == NULL)
    return NDPI_CFG_INVALID_PARAM; /* It shoudn't happen because we already checked it */

  rc = load_config_file_fd(ndpi_str, fd);

  fclose(fd);

  if(rc < 0)
    return rc;

  return NDPI_CFG_OK;
}

/* ****************************************** */

static u_int16_t __get_proto_id(const struct ndpi_detection_module_struct *ndpi_str, const char *proto_name_or_id)
{
  u_int16_t proto_id;
  char *endptr;
  long val;

  /* Let try to decode the string as numerical protocol id */
  /* We can't easily use ndpi_strtonum because we want to be sure that there are no
     others characters after the number */
  errno = 0;    /* To distinguish success/failure after call */
  val = strtol(proto_name_or_id, &endptr, 10);
  if(errno == 0 && *endptr == '\0' &&
     (val >= 0 && val < (long)ndpi_str->num_internal_protocols)) {
    return val;

  }

  /* Try to decode the string as protocol name */
  /* Use the current module, even if `ndpi_finalize_initialization` has not
     been called yet: internal protocols have been already initialized
     and we can get the name of disabled protocols, too */
  proto_id = ndpi_get_proto_by_name(ndpi_str, proto_name_or_id);

  return proto_id;
}

/* ****************************************** */

static ndpi_risk_enum __get_flowrisk_id(const char *flowrisk_name_or_id)
{
  char *endptr;
  long val;
  int i;

  /* Let try to decode the string as numerical flow risk id */
  /* We can't easily use ndpi_strtonum because we want to be sure that there are no
     others characters after the number */
  errno = 0;    /* To distinguish success/failure after call */
  val = strtol(flowrisk_name_or_id, &endptr, 10);
  if(errno == 0 && *endptr == '\0' &&
     (val >= 0 && val < NDPI_MAX_RISK)) {
    return val;

  }

  /* Try to decode the string as flow risk name */
  for(i = 0; i < NDPI_MAX_RISK; i++) {
    if(strcmp(ndpi_risk_shortnames[i], flowrisk_name_or_id) == 0)
      return i;
  }

  return NDPI_NO_RISK;
}

/* ****************************************** */

static char *_get_param_protocol_enable_disable(struct ndpi_detection_module_struct *ndpi_str,
                                                void *_variable, const char *proto,
						char *buf, int buf_len)
{
  struct ndpi_bitmask *bitmask = (struct ndpi_bitmask *)_variable;
  u_int16_t proto_id;

  proto_id = __get_proto_id(ndpi_str, proto);
  if(proto_id == NDPI_PROTOCOL_UNKNOWN)
    return NULL;

  snprintf(buf, buf_len, "%d", !!ndpi_bitmask_is_set(bitmask, proto_id));
  buf[buf_len - 1] = '\0';
  return buf;
}

/* ****************************************** */

static ndpi_cfg_error _set_param_protocol_enable_disable(struct ndpi_detection_module_struct *ndpi_str,
                                                         void *_variable, const char *value,
                                                         const char *min_value, const char *max_value,
                                                         const char *proto, const char *param)
{
  struct ndpi_bitmask *bitmask = (struct ndpi_bitmask *)_variable;
  u_int16_t proto_id;

  (void)ndpi_str;
  (void)min_value;
  (void)max_value;
  (void)param;

  if(strcmp(proto, "any") == 0 ||
     strcmp(proto, "all") == 0 ||
     strcmp(proto, "$PROTO_NAME_OR_ID") == 0) {
    if(strcmp(value, "1") == 0 ||
       strcmp(value, "enable") == 0) {
      ndpi_bitmask_set_all(bitmask);
      return NDPI_CFG_OK;
    }
    if(strcmp(value, "0") == 0 ||
       strcmp(value, "disable") == 0) {
      ndpi_bitmask_reset(bitmask);
      return NDPI_CFG_OK;
    }
  }

  proto_id = __get_proto_id(ndpi_str, proto);
  if(proto_id == NDPI_PROTOCOL_UNKNOWN)
    return NDPI_CFG_INVALID_PARAM;

  if(strcmp(value, "1") == 0 ||
     strcmp(value, "enable") == 0) {
    ndpi_bitmask_set(bitmask, proto_id);
    return NDPI_CFG_OK;
  }
  if(strcmp(value, "0") == 0 ||
     strcmp(value, "disable") == 0) {
    ndpi_bitmask_clear(bitmask, proto_id);
    return NDPI_CFG_OK;
  }
  return NDPI_CFG_INVALID_PARAM;
}

/* ****************************************** */

static char *_get_param_flowrisk_enable_disable(struct ndpi_detection_module_struct *ndpi_str,
                                                void *_variable, const char *proto,
                                                char *buf, int buf_len)
{
  struct ndpi_bitmask *bitmask = (struct ndpi_bitmask *)_variable;
  ndpi_risk_enum flowrisk_id;

  (void)ndpi_str;

  flowrisk_id = __get_flowrisk_id(proto);
  if(flowrisk_id == NDPI_NO_RISK)
    return NULL;

  snprintf(buf, buf_len, "%d", !!ndpi_bitmask_is_set(bitmask, flowrisk_id));
  buf[buf_len - 1] = '\0';
  return buf;
}

/* ****************************************** */

static ndpi_cfg_error _set_param_flowrisk_enable_disable(struct ndpi_detection_module_struct *ndpi_str,
                                                         void *_variable, const char *value,
                                                         const char *min_value, const char *max_value,
                                                         const char *proto, const char *_param)
{
  struct ndpi_bitmask *bitmask = (struct ndpi_bitmask *)_variable;
  ndpi_risk_enum flowrisk_id;
  char param[128] = {0};

  (void)ndpi_str;
  (void)min_value;
  (void)max_value;
  (void)proto;

  if(strncmp(_param, "flow_risk.", 10) != 0)
    return NDPI_CFG_INVALID_PARAM;

  _param += 10; /* Strip initial "flow_risk." */

  if(strlen(_param) > 5 &&
     strncmp(_param + (strlen(_param) - 5), ".info", 5) == 0)
    memcpy(param, _param, ndpi_min(strlen(_param) - 5, sizeof(param) - 1)); /* Strip trailing ".info" */
  else
    strncpy(param, _param, sizeof(param) - 1);

  if(strcmp(param, "any") == 0 ||
     strcmp(param, "all") == 0 ||
     strcmp(param, "$FLOWRISK_NAME_OR_ID") == 0) {
    if(strcmp(value, "1") == 0 ||
       strcmp(value, "enable") == 0) {
      ndpi_bitmask_set_all(bitmask);
      return NDPI_CFG_OK;
    }
    if(strcmp(value, "0") == 0 ||
       strcmp(value, "disable") == 0) {
      ndpi_bitmask_reset(bitmask);
      return NDPI_CFG_OK;
    }
  }

  flowrisk_id = __get_flowrisk_id(param);
  if(flowrisk_id == NDPI_NO_RISK)
    return NDPI_CFG_INVALID_PARAM;

  if(strcmp(value, "1") == 0 ||
     strcmp(value, "enable") == 0) {
    ndpi_bitmask_set(bitmask, flowrisk_id);
    return NDPI_CFG_OK;
  }
  if(strcmp(value, "0") == 0 ||
     strcmp(value, "disable") == 0) {
    ndpi_bitmask_clear(bitmask, flowrisk_id);
    return NDPI_CFG_OK;
  }
  return NDPI_CFG_INVALID_PARAM;
}

/* ****************************************** */
/* ****************************************** */

static AC_ERROR_t ac_walk_proto_id(AC_AUTOMATA_t *thiz, AC_NODE_t *n, int idx, void *data) {
  __ndpi_unused_param(thiz);
  __ndpi_unused_param(idx);
  __ndpi_unused_param(data);

  if(n->matched_patterns) {
    ndpi_str_hash *h = (ndpi_str_hash*)data;
    int i;

    for(i=0; i<n->matched_patterns->num; i++) {
      AC_PATTERN_t *p = &n->matched_patterns->patterns[i];

      ndpi_hash_add_entry(&h, p->astring, strlen(p->astring), p->rep.number, NULL);
    }
  }

  return ACERR_SUCCESS;
}

/* ****************************************** */

static AC_ERROR_t ac_walk_category_id(AC_AUTOMATA_t *thiz, AC_NODE_t *n, int idx, void *data) {
  __ndpi_unused_param(thiz);
  __ndpi_unused_param(idx);
  __ndpi_unused_param(data);

  if(n->matched_patterns) {
    ndpi_str_hash *h = (ndpi_str_hash*)data;
    int i;

    for(i=0; i<n->matched_patterns->num; i++) {
      AC_PATTERN_t *p = &n->matched_patterns->patterns[i];

      ndpi_hash_add_entry(&h, p->astring, strlen(p->astring), p->rep.category, NULL);
    }
  }

  return ACERR_SUCCESS;
}

/* ****************************************** */

static void _dump_host_based_protocol(struct ndpi_detection_module_struct *ndpi_str,
				      ndpi_hash_walk_iter walker, bool walk_proto_id,
				      void *data) {
  ndpi_str_hash *h;

  if(!ndpi_str->host_automa.ac_automa)
    return;

  ndpi_hash_init(&h);
  ac_automata_walk((AC_AUTOMATA_t *)ndpi_str->host_automa.ac_automa,
		   walk_proto_id ? ac_walk_proto_id : ac_walk_category_id, NULL, h);
  ndpi_hash_walk(&h, walker, data);
  ndpi_hash_free(&h);
}

/* ****************************************** */

void ndpi_dump_host_based_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
				      ndpi_hash_walk_iter walker, void *data) {
  if(!ndpi_str)
    return;
  _dump_host_based_protocol(ndpi_str, walker, true /* protocol id */, data);
}

/* ****************************************** */

void ndpi_dump_host_based_category_id(struct ndpi_detection_module_struct *ndpi_str,
				      ndpi_hash_walk_iter walker, void *data) {
  if(!ndpi_str)
    return;
  _dump_host_based_protocol(ndpi_str, walker, false /* category */, data);
}
