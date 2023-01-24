#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration;
  ndpi_serializer serializer, serializer_cloned, deserializer;
  ndpi_serialization_format fmt;
  int rc;
  std::vector<char>d;
  char kbuf[32];
  u_int32_t buffer_len;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  fmt = static_cast<ndpi_serialization_format>(fuzzed_data.ConsumeIntegralInRange(1, 3));

  if (fuzzed_data.ConsumeBool())
    rc = ndpi_init_serializer(&serializer, fmt);
  else
    rc = ndpi_init_serializer_ll(&serializer, fmt, fuzzed_data.ConsumeIntegralInRange(0, 64));

  if (rc != 0)
    return 0;
    
  if (fmt == ndpi_serialization_format_csv)
    ndpi_serializer_set_csv_separator(&serializer, ',');

  num_iteration = fuzzed_data.ConsumeIntegralInRange(0, 16);
  for (i = 0; i < num_iteration; i++) {
    memset(kbuf, '\0', sizeof(kbuf)); /* It is also used as binary key */
    snprintf(kbuf, sizeof(kbuf), "Key %d", i);

    ndpi_serialize_uint32_uint32(&serializer, i, fuzzed_data.ConsumeIntegral<u_int32_t>());
    ndpi_serialize_uint32_int32(&serializer, i, fuzzed_data.ConsumeIntegral<int32_t>());
    ndpi_serialize_uint32_uint64(&serializer, i, fuzzed_data.ConsumeIntegral<u_int64_t>());
    ndpi_serialize_uint32_int64(&serializer, i, fuzzed_data.ConsumeIntegral<int64_t>());
    ndpi_serialize_uint32_float(&serializer, i, fuzzed_data.ConsumeFloatingPoint<float>(), "%f");
    if (fmt != ndpi_serialization_format_tlv)
      ndpi_serialize_uint32_double(&serializer, i, fuzzed_data.ConsumeFloatingPoint<double>(), "%lf");
    d = fuzzed_data.ConsumeBytes<char>(16);
    ndpi_serialize_uint32_binary(&serializer, i, d.data(), d.size());
    ndpi_serialize_uint32_string(&serializer, i, fuzzed_data.ConsumeBytesAsString(8).c_str());
    ndpi_serialize_uint32_boolean(&serializer, i, fuzzed_data.ConsumeIntegral<int8_t>());

    ndpi_serialize_string_uint32(&serializer, kbuf, fuzzed_data.ConsumeIntegral<u_int32_t>());
    ndpi_serialize_string_int32(&serializer, kbuf, fuzzed_data.ConsumeIntegral<int32_t>());
    ndpi_serialize_string_uint64(&serializer, kbuf, fuzzed_data.ConsumeIntegral<u_int64_t>());
    ndpi_serialize_string_int64(&serializer, kbuf, fuzzed_data.ConsumeIntegral<int64_t>());
    ndpi_serialize_string_float(&serializer, kbuf, fuzzed_data.ConsumeFloatingPoint<float>(), "%f");
    if (fmt != ndpi_serialization_format_tlv)
      ndpi_serialize_string_double(&serializer, kbuf, fuzzed_data.ConsumeFloatingPoint<double>(), "%lf");
    ndpi_serialize_string_string(&serializer, kbuf, fuzzed_data.ConsumeBytesAsString(8).c_str());
    ndpi_serialize_string_boolean(&serializer, kbuf, fuzzed_data.ConsumeIntegral<int8_t>());

    ndpi_serialize_binary_uint32(&serializer, kbuf, sizeof(kbuf), fuzzed_data.ConsumeIntegral<u_int32_t>());
    ndpi_serialize_binary_int32(&serializer, kbuf, sizeof(kbuf), fuzzed_data.ConsumeIntegral<int32_t>());
    ndpi_serialize_binary_uint64(&serializer, kbuf, sizeof(kbuf), fuzzed_data.ConsumeIntegral<u_int64_t>());
    ndpi_serialize_binary_int64(&serializer, kbuf, sizeof(kbuf), fuzzed_data.ConsumeIntegral<int64_t>());
    ndpi_serialize_binary_float(&serializer, kbuf, sizeof(kbuf), fuzzed_data.ConsumeFloatingPoint<float>(), "%f");
    if (fmt != ndpi_serialization_format_tlv)
      ndpi_serialize_binary_double(&serializer, kbuf, sizeof(kbuf), fuzzed_data.ConsumeFloatingPoint<double>(), "%lf");
    ndpi_serialize_binary_boolean(&serializer, kbuf, sizeof(kbuf), fuzzed_data.ConsumeIntegral<int8_t>());
    d = fuzzed_data.ConsumeBytes<char>(16);
    ndpi_serialize_binary_binary(&serializer, kbuf, sizeof(kbuf), d.data(), d.size());

    if ((i & 0x3) == 0x3)
      ndpi_serialize_end_of_record(&serializer);
  }

  ndpi_serializer_create_snapshot(&serializer);

  if (fuzzed_data.ConsumeBool()) {
    ndpi_serialize_start_of_block(&serializer, "Block");
    memset(kbuf, '\0', sizeof(kbuf)); /* It is also used as binary key */
    snprintf(kbuf, sizeof(kbuf), "K-Ignored");
    ndpi_serialize_uint32_uint32(&serializer, i, fuzzed_data.ConsumeIntegral<u_int32_t>());
    ndpi_serialize_string_string(&serializer, kbuf, fuzzed_data.ConsumeBytesAsString(8).c_str());
    ndpi_serialize_string_float(&serializer, kbuf, fuzzed_data.ConsumeFloatingPoint<float>(), "%f");
    ndpi_serialize_binary_boolean(&serializer, kbuf, sizeof(kbuf), fuzzed_data.ConsumeIntegral<int8_t>());
    ndpi_serialize_end_of_block(&serializer);
  }

  if (fuzzed_data.ConsumeBool()) {
    ndpi_serialize_start_of_block_uint32(&serializer, 0);
    memset(kbuf, '\0', sizeof(kbuf)); /* It is also used as binary key */
    snprintf(kbuf, sizeof(kbuf), "K32-Ignored");
    ndpi_serialize_uint32_uint32(&serializer, i, fuzzed_data.ConsumeIntegral<u_int32_t>());
    ndpi_serialize_string_string(&serializer, kbuf, fuzzed_data.ConsumeBytesAsString(8).c_str());
    ndpi_serialize_string_float(&serializer, kbuf, fuzzed_data.ConsumeFloatingPoint<float>(), "%f");
    ndpi_serialize_binary_boolean(&serializer, kbuf, sizeof(kbuf), fuzzed_data.ConsumeIntegral<int8_t>());
    ndpi_serialize_end_of_block(&serializer);
  }

  if (fuzzed_data.ConsumeBool())
    ndpi_serializer_rollback_snapshot(&serializer);

  if (fmt == ndpi_serialization_format_json) {

    ndpi_serialize_start_of_list(&serializer, "List");

    num_iteration = fuzzed_data.ConsumeIntegralInRange(0, 8);
    for (i = 0; i < num_iteration; i++) {
      memset(kbuf, '\0', sizeof(kbuf)); /* It is also used as binary key */
      snprintf(kbuf, sizeof(kbuf), "Ignored");
      ndpi_serialize_uint32_uint32(&serializer, i, fuzzed_data.ConsumeIntegral<u_int32_t>());
      ndpi_serialize_string_string(&serializer, kbuf, fuzzed_data.ConsumeBytesAsString(8).c_str());
      ndpi_serialize_string_float(&serializer, kbuf, fuzzed_data.ConsumeFloatingPoint<float>(), "%f");
      ndpi_serialize_binary_boolean(&serializer, kbuf, sizeof(kbuf), fuzzed_data.ConsumeIntegral<int8_t>());
    }

    ndpi_serialize_end_of_list(&serializer);
    ndpi_serialize_string_string(&serializer, "Last", "Ok");
  } else if (fmt == ndpi_serialization_format_csv) {
    ndpi_serializer_get_header(&serializer, &buffer_len);
    ndpi_serializer_get_buffer(&serializer, &buffer_len);
  } else {
    /* Conversion from tlv to json */
    rc = ndpi_init_deserializer(&deserializer, &serializer);
    if (rc == 0) {
      rc = ndpi_init_serializer_ll(&serializer_cloned, ndpi_serialization_format_json, fuzzed_data.ConsumeIntegralInRange(0, 2048));
      if (rc == 0) {
        ndpi_deserialize_clone_all(&deserializer, &serializer_cloned);
        ndpi_serializer_get_buffer(&serializer_cloned, &buffer_len);
        ndpi_term_serializer(&serializer_cloned);
      }
    }
  }

  ndpi_term_serializer(&serializer);

  return 0;
}
