#include "ndpi_api.h"
#include "ndpi_private.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>

struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
struct ndpi_flow_struct *flow = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  const u_int8_t *crypto_data;
  uint64_t crypto_data_len;
  u_int32_t first_int, version = 0;

  if(ndpi_info_mod == NULL) {
    fuzz_init_detection_module(&ndpi_info_mod, NULL);

    flow = ndpi_calloc(1, SIZEOF_FLOW_STRUCT);
  }

  if(Size < 4)
    return 0;

  first_int = ntohl(*(u_int32_t *)Data);
  if((first_int % 4) == 0)
    version = 0x00000001; /* v1 */
  else if((first_int % 4) == 1)
    version = 0x51303530; /* Q050 */
  else if((first_int % 4) == 2)
    version = 0x51303436; /* Q046 */
  else if((first_int % 4) == 3)
    version = 0x709A50C4; /* v2 */

  memset(flow, '\0', sizeof(*flow));
  flow->detected_protocol_stack[0] = NDPI_PROTOCOL_QUIC;
  flow->l4_proto = IPPROTO_UDP;
  flow->protos.tls_quic.quic_version = version;

  crypto_data = get_crypto_data(ndpi_info_mod, flow, (u_int8_t *)Data + 4, Size - 4, &crypto_data_len);

  if(crypto_data) {
    if(!is_version_with_tls(version)) {
      process_chlo(ndpi_info_mod, flow, crypto_data, crypto_data_len);
    } else {
      process_tls(ndpi_info_mod, flow, crypto_data, crypto_data_len);
    }
  }

  ndpi_free_flow_data(flow);

  return 0;
}
