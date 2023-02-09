#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

static void process_ptree_data(ndpi_prefix_t *prefix, void *data) {
  /* Nothing to do */
  assert(prefix && data == NULL);
}
static void process3_ptree_data(ndpi_patricia_node_t *node, void *data, void *user_data) {
  /* Nothing to do */
  assert(node && data == NULL && user_data == NULL);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration, ip_len;
  ndpi_patricia_tree_t *p, *p_cloned;
  u_int16_t maxbits;
  int is_ipv6, is_added = 0;
  ndpi_prefix_t prefix, prefix_added;
  u_char *ip;
  ndpi_patricia_node_t *node;

  /* Just to have some data */
  if (fuzzed_data.remaining_bytes() < 1024)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  is_ipv6 = fuzzed_data.ConsumeBool();
  if (is_ipv6)
    maxbits = 128;
  else
    maxbits = 32;

  p = ndpi_patricia_new(maxbits);

  ndpi_patricia_get_maxbits(p);
  ndpi_patricia_process(p, process_ptree_data);
  ndpi_patricia_walk_tree_inorder(p, process3_ptree_data, NULL);

  /* "Random" add */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    if (!is_ipv6) {
      if(fuzzed_data.remaining_bytes() > 4) {
        std::vector<u_int8_t>data = fuzzed_data.ConsumeBytes<u_int8_t>(4);
	ip = data.data();
        ip_len = fuzzed_data.ConsumeIntegralInRange(0, 32);
        ndpi_fill_prefix_v4(&prefix, (struct in_addr *)ip, ip_len, 32);
        node = ndpi_patricia_lookup(p, &prefix);
        /* Keep one random node really added */
	if (node && is_added == 0 && fuzzed_data.ConsumeBool()) {
          is_added = 1;
          prefix_added = prefix;
	  /* Some random operations on this node */
          ndpi_patricia_get_node_prefix(node);
          ndpi_patricia_get_node_bits(node);
          ndpi_patricia_set_node_data(node, NULL);
          assert(ndpi_patricia_get_node_data(node) == NULL);
          ndpi_patricia_set_node_u64(node, 0);
          assert(ndpi_patricia_get_node_u64(node) == 0);
	}
      }
    } else {
      if(fuzzed_data.remaining_bytes() > 16) {
        std::vector<u_int8_t>data = fuzzed_data.ConsumeBytes<u_int8_t>(16);
	ip = data.data();
        ip_len = fuzzed_data.ConsumeIntegralInRange(0, 128);
        ndpi_fill_prefix_v6(&prefix, (const struct in6_addr *)ip, ip_len, 128);
        node = ndpi_patricia_lookup(p, &prefix);
        /* Keep one random node really added */
	if (node && is_added == 0 && fuzzed_data.ConsumeBool()) {
          is_added = 1;
          prefix_added = prefix;
	  /* Some random operations on this node */
          ndpi_patricia_get_node_prefix(node);
          ndpi_patricia_get_node_bits(node);
          ndpi_patricia_set_node_data(node, NULL);
          assert(ndpi_patricia_get_node_data(node) == NULL);
          ndpi_patricia_set_node_u64(node, 0);
          assert(ndpi_patricia_get_node_u64(node) == 0);
	}
      }
    }
  }

  ndpi_patricia_process(p, process_ptree_data);
  ndpi_patricia_walk_tree_inorder(p, process3_ptree_data, NULL);

  /* "Random" exact search. Remove if found */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    if (!is_ipv6) {
      if(fuzzed_data.remaining_bytes() > 4) {
        std::vector<u_int8_t>data = fuzzed_data.ConsumeBytes<u_int8_t>(4);
	ip = data.data();
        ip_len = fuzzed_data.ConsumeIntegralInRange(0, 32);
        ndpi_fill_prefix_v4(&prefix, (struct in_addr *)ip, ip_len, 32);
        node = ndpi_patricia_search_exact(p, &prefix);
	if (node)
          ndpi_patricia_remove(p, node);
      }
    } else {
      if(fuzzed_data.remaining_bytes() > 16) {
        std::vector<u_int8_t>data = fuzzed_data.ConsumeBytes<u_int8_t>(16);
	ip = data.data();
        ip_len = fuzzed_data.ConsumeIntegralInRange(0, 128);
        ndpi_fill_prefix_v6(&prefix, (const struct in6_addr *)ip, ip_len, 128);
        node = ndpi_patricia_search_exact(p, &prefix);
	if (node)
          ndpi_patricia_remove(p, node);
      }
    }
  }
  /* Exact search of an added node */
  if (is_added)
    ndpi_patricia_search_exact(p, &prefix_added);

  /* "Random" best search. Remove if found */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    if (!is_ipv6) {
      if(fuzzed_data.remaining_bytes() > 4) {
        std::vector<u_int8_t>data = fuzzed_data.ConsumeBytes<u_int8_t>(4);
	ip = data.data();
        ip_len = fuzzed_data.ConsumeIntegralInRange(0, 32);
        ndpi_fill_prefix_v4(&prefix, (struct in_addr *)ip, ip_len, 32);
        node = ndpi_patricia_search_best(p, &prefix);
	if (node)
          ndpi_patricia_remove(p, node);
      }
    } else {
      if(fuzzed_data.remaining_bytes() > 16) {
        std::vector<u_int8_t>data = fuzzed_data.ConsumeBytes<u_int8_t>(16);
	ip = data.data();
        ip_len = fuzzed_data.ConsumeIntegralInRange(0, 128);
        ndpi_fill_prefix_v6(&prefix, (const struct in6_addr *)ip, ip_len, 128);
        node = ndpi_patricia_search_best(p, &prefix);
	if (node)
          ndpi_patricia_remove(p, node);
      }
    }
  }
  /* Best search of an added node */
  if (is_added)
    ndpi_patricia_search_best(p, &prefix_added);

  p_cloned = ndpi_patricia_clone(p);
  
  ndpi_patricia_process(p_cloned, process_ptree_data);
  ndpi_patricia_walk_tree_inorder(p_cloned, process3_ptree_data, NULL);


  ndpi_patricia_destroy(p, NULL);
  ndpi_patricia_destroy(p_cloned, NULL);

  return 0;
}
