#include "ndpi_api.h"

#include <stdint.h>
#include <stdio.h>

struct ndpi_detection_module_struct *ndpi_info_mod = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  uint8_t protocol_was_guessed;

  if (ndpi_info_mod == NULL) {
    ndpi_info_mod = ndpi_init_detection_module(ndpi_enable_ja3_plus);
    NDPI_PROTOCOL_BITMASK all, debug_bitmask;
    NDPI_BITMASK_SET_ALL(all);
    NDPI_BITMASK_SET_ALL(debug_bitmask);
    ndpi_set_protocol_detection_bitmask2(ndpi_info_mod, &all);
    ndpi_set_log_level(ndpi_info_mod, 4);
    ndpi_set_debug_bitmask(ndpi_info_mod, debug_bitmask);
    ndpi_finalize_initialization(ndpi_info_mod);
  }

  struct ndpi_flow_struct *ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
  memset(ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
  ndpi_detection_process_packet(ndpi_info_mod, ndpi_flow, Data, Size, 0);
  ndpi_detection_giveup(ndpi_info_mod, ndpi_flow, 1, &protocol_was_guessed);
  ndpi_free_flow(ndpi_flow);

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
            (argc > 0 ? argv[0] : "fuzz_process_packet_with_main"));
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
