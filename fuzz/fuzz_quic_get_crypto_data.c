#include "ndpi_api.h"

#include <stdint.h>
#include <stdio.h>

struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
struct ndpi_flow_struct *flow = NULL;

extern const uint8_t *get_crypto_data(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow,
				      uint32_t version,
				      u_int8_t *clear_payload, uint32_t clear_payload_len,
				      uint64_t *crypto_data_len);
extern void process_tls(struct ndpi_detection_module_struct *ndpi_struct,
			struct ndpi_flow_struct *flow,
			const u_int8_t *crypto_data, uint32_t crypto_data_len,
			uint32_t version);
extern void process_chlo(struct ndpi_detection_module_struct *ndpi_struct,
			 struct ndpi_flow_struct *flow,
			 const u_int8_t *crypto_data, uint32_t crypto_data_len);
extern int is_version_with_tls(uint32_t version);


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  const u_int8_t *crypto_data;
  uint64_t crypto_data_len;
  u_int32_t first_int, version = 0;

  if(ndpi_info_mod == NULL) {
    ndpi_info_mod = ndpi_init_detection_module(ndpi_enable_ja3_plus);
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_info_mod, &all);
#if 0
    NDPI_PROTOCOL_BITMASK debug_bitmask;
    NDPI_BITMASK_SET_ALL(debug_bitmask);
    ndpi_set_log_level(ndpi_info_mod, 4);
    ndpi_set_debug_bitmask(ndpi_info_mod, debug_bitmask);
#endif
    ndpi_finalize_initialization(ndpi_info_mod);

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

  crypto_data = get_crypto_data(ndpi_info_mod, flow, version, (u_int8_t *)Data + 4, Size - 4, &crypto_data_len);

  if(crypto_data) {
    if(!is_version_with_tls(version)) {
      process_chlo(ndpi_info_mod, flow, crypto_data, crypto_data_len);
    } else {
      process_tls(ndpi_info_mod, flow, crypto_data, crypto_data_len, version);
    }
  }

  ndpi_free_flow_data(flow);

  return 0;
}

#ifdef BUILD_MAIN
int main(int argc, char ** argv)
{
  FILE * data_file;
  long data_file_size;
  uint8_t * data_buffer;
  int test_retval;

  if (argc != 2) {
    fprintf(stderr, "usage: %s: [data-file]\n",
            (argc > 0 ? argv[0] : "fuzz_quic_get_crypto_data"));
    return 1;
  }

  data_file = fopen(argv[1], "r");
  if (data_file == NULL) {
    perror("fopen failed");
    return 1;
  }

  if (fseek(data_file, 0, SEEK_END) != 0) {
    perror("fseek(SEEK_END) failed");
    fclose(data_file);
    return 1;
  }

  data_file_size = ftell(data_file);
  if (data_file_size < 0) {
    perror("ftell failed");
    fclose(data_file);
    return 1;
  }

  if (fseek(data_file, 0, SEEK_SET) != 0) {
    perror("fseek(0, SEEK_SET)  failed");
    fclose(data_file);
    return 1;
  }

  data_buffer = malloc(data_file_size);
  if (data_buffer == NULL) {
    perror("malloc failed");
    fclose(data_file);
    return 1;
  }

  if (fread(data_buffer, sizeof(*data_buffer), data_file_size, data_file) != (size_t)data_file_size) {
    perror("fread failed");
    fclose(data_file);
    free(data_buffer);
    return 1;
  }

  test_retval = LLVMFuzzerTestOneInput(data_buffer, data_file_size);
  fclose(data_file);
  free(data_buffer);

  return test_retval;
}
#endif
