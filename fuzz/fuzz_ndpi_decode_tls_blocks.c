/*
 * fuzz_ndpi_decode_tls_blocks
 *
 * What it tests:
 *   ndpi_decode_tls_blocks() in src/lib/ndpi_utils.c, which in turn invokes
 *   ndpi_hex_decode(). The decoder consumes an attacker-controlled byte
 *   stream, hex-decodes it, then walks it as { block_type, len_hi, len_lo }
 *   triples. Both the hex decoder and the structural parser are exposed.
 *
 * Expected input format:
 *   Arbitrary bytes (interpreted as hex ASCII by the target). No state, one
 *   shot per invocation; all memory returned by the target is freed here.
 */

#include "ndpi_api.h"

#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  u_int8_t num_blocks = 0;
  struct ndpi_tls_block *blocks;

  if (size > (u_int)UINT32_MAX)
    return 0;

  blocks = ndpi_decode_tls_blocks((const u_char *)data,
                                  (u_int)size,
                                  &num_blocks);
  if (blocks != NULL)
    ndpi_free(blocks);

  return 0;
}
