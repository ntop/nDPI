#include "reader_util.h"
#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <pcap/pcap.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <libgen.h>

#ifdef ENABLE_PCAP_L7_MUTATOR
#include "pl7m.h"
#endif

#ifdef ENABLE_NALLOC
#include "nallocinc.c"
#endif

struct ndpi_workflow_prefs *prefs = NULL;
struct ndpi_workflow *workflow = NULL;
struct ndpi_global_context *g_ctx;

u_int8_t enable_payload_analyzer = 0;
u_int8_t enable_flow_stats = 1;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 0, max_num_tcp_dissected_pkts = 0; /* Disable limits at application layer */;
int alloc_size_stats = 0;
FILE *fingerprint_fp = NULL;
char *addr_dump_path = NULL;
int monitoring_enabled = 1;
u_int8_t enable_doh_dot_detection = 0;

static char *path = NULL;

extern void ndpi_report_payload_stats(FILE *out);

#ifdef CRYPT_FORCE_NO_AESNI
extern int force_no_aesni;
#endif

#ifdef ENABLE_PCAP_L7_MUTATOR
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                               size_t MaxSize, unsigned int Seed) {
  return pl7m_mutator(Data, Size, MaxSize, Seed);
}
#endif

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;

  path = dirname(strdup(*argv[0])); /* No errors; no free! */
  return 0;
}

static void node_cleanup_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;

  (void)depth;
  (void)user_data;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if((!flow->detection_completed) && flow->ndpi_flow) {
      flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct,
                                                      flow->ndpi_flow);
    }

    process_ndpi_collected_info(workflow, flow);
  }
}

static void fn_flow_callback(struct ndpi_workflow *w, struct ndpi_flow_info *f, void *d)
{
  (void)w;
  (void)f;
  (void)d;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  pcap_t * pkts;
  const u_char *pkt;
  struct pcap_pkthdr *header;
  int r;
  char errbuf[PCAP_ERRBUF_SIZE];
  u_int i;
  FILE *fd;
  char name[256];

  if (prefs == NULL) {
    prefs = calloc(sizeof(struct ndpi_workflow_prefs), 1); /* No failure here */
    prefs->decode_tunnels = 1;
    prefs->num_roots = 16;
    prefs->max_ndpi_flows = 16 * 1024 * 1024;
    prefs->quiet_mode = 0;

#ifdef ENABLE_MEM_ALLOC_FAILURES
    fuzz_set_alloc_callbacks();
#endif

    g_ctx = ndpi_global_init();

    workflow = ndpi_workflow_init(prefs, NULL /* pcap handler will be set later */, 0, ndpi_serialization_format_json, g_ctx);

    ndpi_workflow_set_flow_callback(workflow, fn_flow_callback, NULL);

    ndpi_set_config(workflow->ndpi_struct, NULL, "log.level", "3");
    ndpi_set_config(workflow->ndpi_struct, "all", "log", "1");

    sprintf(name, "%s/public_suffix_list.dat", path);
    assert(ndpi_load_domain_suffixes(workflow->ndpi_struct, name) >= 0);
    sprintf(name, "%s/lists/", path);
    assert(ndpi_load_categories_dir(workflow->ndpi_struct, name) >= 0);
    sprintf(name, "%s/lists/protocols/", path);
    assert(ndpi_load_protocols_dir(workflow->ndpi_struct, name) >= 0);
    sprintf(name, "%s/protos.txt", path);
    assert(ndpi_load_protocols_file(workflow->ndpi_struct, name) >= 0);
    sprintf(name, "%s/categories.txt", path);
    assert(ndpi_load_categories_file(workflow->ndpi_struct, name, NULL) >= 0);
    sprintf(name, "%s/risky_domains.txt", path);
    assert(ndpi_load_risk_domain_file(workflow->ndpi_struct, name) >= 0);
    sprintf(name, "%s/ja4_fingerprints.csv", path);
    assert(ndpi_load_malicious_ja4_file(workflow->ndpi_struct, name) >= 0);
    sprintf(name, "%s/tcp_fingerprints.csv", path);
    assert(ndpi_load_tcp_fingerprint_file(workflow->ndpi_struct, name) >= 0);
    sprintf(name, "%s/sha1_fingerprints.csv", path);
    assert(ndpi_load_malicious_sha1_file(workflow->ndpi_struct, name) >= 0);
    sprintf(name, "%s", path);
    assert(ndpi_load_protocol_plugins(workflow->ndpi_struct, name) >= 0); /* Plugins are not really used while fuzzing, yet */

#ifdef ENABLE_ONLY_SUBCLASSIFICATION
    sprintf(name, "%s/config_only_classification.txt", path);
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "filename.config", name) == NDPI_CFG_OK);
#else

    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "packets_limit_per_flow", "255") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "flow.track_payload", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "tcp_ack_payload_heuristic", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "fully_encrypted_heuristic", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "dns", "subclassification", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "application_blocks_tracking", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "max_num_blocks_to_analyze", "8") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "tls_blocks_show_timing", "0") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "metadata.ja_ignore_ephemeral_tls_extn", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "metadata.ndpifp_ignore_sni_tls_extn", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "metadata.ja_data", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "ssh", "metadata.ssh_data", "1") == NDPI_CFG_OK);
#ifndef ENABLE_CONFIG2
    assert(ndpi_set_config(workflow->ndpi_struct, "stun", "max_packets_extra_dissection", "40") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "zoom", "max_packets_extra_dissection", "255") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "rtp", "search_for_stun", "1") == NDPI_CFG_OK);
#endif
    assert(ndpi_set_config(workflow->ndpi_struct, "openvpn", "dpi.heuristics", "0x01") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "openvpn", "dpi.heuristics.num_messages", "20") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "metadata.ja4r_fingerprint", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "dpi.heuristics", "0x07") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "dpi.heuristics.max_packets_extra_dissection", "40") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "all", "monitoring", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "dpi.address_cache_size", "8192") == NDPI_CFG_OK);

    /* Roaring code doesn't handle memory allocation failures */
#ifdef ENABLE_NALLOC
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "hostname_dns_check", "0") == NDPI_CFG_OK);
#else
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "hostname_dns_check", "1") == NDPI_CFG_OK);
#endif

#ifdef ENABLE_CONFIG2
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "flow_risk.all.info", "0") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "metadata.tcp_fingerprint_format", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "metadata.ndpi_fingerprint_format", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, NULL, "metadata.ndpi_fingerprint_ignore_tcp_fp", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "max_num_blocks_to_analyze", "8") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "tls_blocks_show_timing", "0") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "metadata.ja_ignore_ephemeral_tls_extn", "1") == NDPI_CFG_OK);
    assert(ndpi_set_config(workflow->ndpi_struct, "tls", "metadata.ndpifp_ignore_sni_tls_extn", "1") == NDPI_CFG_OK);

    addr_dump_path = "/tmp/";
#endif

#endif /* ENABLE_ONLY_SUBCLASSIFICATION */

    ndpi_finalize_initialization(workflow->ndpi_struct);

#ifdef ENABLE_FINGERPRINT_FP
    fingerprint_fp = stdout;
#endif

#ifdef CRYPT_FORCE_NO_AESNI
    force_no_aesni = 1;
#endif

#ifdef ENABLE_PAYLOAD_ANALYZER
   enable_payload_analyzer = 1;
#endif
  }

#ifdef ENABLE_MEM_ALLOC_FAILURES
  /* Don't fail memory allocations until init phase is done */
  fuzz_set_alloc_callbacks_and_seed(Size);
#endif

  fd = buffer_to_file(Data, Size);
  if (fd == NULL)
    return 0;

  pkts = pcap_fopen_offline(fd, errbuf);
  if (pkts == NULL) {
    fclose(fd);
    return 0;
  }
  if (ndpi_is_datalink_supported(pcap_datalink(pkts)) == 0)
  {
    /* Do not fail if the datalink type is not supported (may happen often during fuzzing). */
    pcap_close(pkts);
    return 0;
  }

  workflow->pcap_handle = pkts;
  /* Init flow tree */
  workflow->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));
  if(!workflow->ndpi_flows_root) {
    pcap_close(pkts);
    return 0;
  }

#ifdef ENABLE_NALLOC
  nalloc_init("nalloc");
  nalloc_start(Data, Size);
#endif

  header = NULL;
  r = pcap_next_ex(pkts, &header, &pkt);
  while (r > 0) {
    /* allocate an exact size buffer to check overflows */
    uint8_t *packet_checked = malloc(header->caplen);

    if(packet_checked) {
      ndpi_risk flow_risk;
      struct ndpi_flow_info *flow = NULL; /* unused */

      memcpy(packet_checked, pkt, header->caplen);
      ndpi_workflow_process_packet(workflow, header, packet_checked, &flow_risk, &flow);
      free(packet_checked);
    }

    r = pcap_next_ex(pkts, &header, &pkt);
  }
  pcap_close(pkts);

  /* Free flow trees */
  for(i = 0; i < workflow->prefs.num_roots; i++) {
    ndpi_twalk(workflow->ndpi_flows_root[i], node_cleanup_walker, NULL);
    ndpi_tdestroy(workflow->ndpi_flows_root[i], ndpi_flow_info_freer);
  }
  ndpi_free(workflow->ndpi_flows_root);
  /* Free payload analyzer data */
  if(enable_payload_analyzer)
    ndpi_report_payload_stats(stdout);

#ifdef ENABLE_PAYLOAD_ANALYZER
  ndpi_update_params(SPLT_PARAM_TYPE, "splt_param.txt");
  ndpi_update_params(BD_PARAM_TYPE, "bd_param.txt");
  ndpi_update_params(2, ""); /* invalid */
#endif

#ifdef ENABLE_NALLOC
  nalloc_end();
#endif

  return 0;
}
