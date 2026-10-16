#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"

/* This fuzzer feeds *untrusted, attacker-controlled* bytes directly to the
 * nDPI TLV deserializer public API (ndpi_init_deserializer_buf() + the
 * deserialize/clone/iterate functions).
 *
 * This is exactly the usage pattern of an embedder that receives nDPI TLV
 * records from the network (e.g. a collector reading them off a socket).
 */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  /* The deserializer needs at least a 2-byte header (version + format) */
  if(size < 2)
    return 0;

  /* ndpi_init_deserializer_buf() does NOT copy the input: it stores the
   * pointer and reads through it in place. Copy into an exactly-sized heap
   * buffer so that any read past the logical end lands in an ASan redzone
   * and is reported, instead of silently hitting valid adjacent memory.
   *
   * Use libc malloc() (not ndpi_malloc()) on purpose: this models the bytes
   * an embedder received off the network, which do not come from nDPI's
   * allocator, and keeps the input buffer present regardless of the
   * allocation-failure injection above (so the truncated-input defects
   * reproduce deterministically). */
  u_int8_t *buf = (u_int8_t *) malloc(size);
  if(buf == NULL)
    return 0;
  memcpy(buf, data, size);

  /* Force a valid version byte so the version gate doesn't reject most inputs;
   * everything after it (format + TLV records) stays attacker-controlled. */
  buf[0] = 1;

  ndpi_deserializer deserializer;
  ndpi_serializer serializer;
  int rc;

  /* 1) Clone the current item into a TLV serializer (ndpi_deserialize_clone_item) */
  if(ndpi_init_deserializer_buf(&deserializer, buf, size) == 0) {
    if(ndpi_init_serializer(&serializer, ndpi_serialization_format_tlv) == 0) {
      ndpi_deserialize_clone_item(&deserializer, &serializer);
      ndpi_term_serializer(&serializer);
    }
  }

  /* 2) Clone the whole stream into a JSON serializer (ndpi_deserialize_clone_all) */
  if(ndpi_init_deserializer_buf(&deserializer, buf, size) == 0) {
    if(ndpi_init_serializer(&serializer, ndpi_serialization_format_json) == 0) {
      ndpi_deserialize_clone_all(&deserializer, &serializer);
      ndpi_term_serializer(&serializer);
    }
  }

  /* 3) Walk the stream with the public iteration API, reading keys/values
   *    according to the advertised types (exercises ndpi_deserialize_next()
   *    and the single_string / single value readers). Bounded to avoid long
   *    loops on adversarial inputs. */
  if(ndpi_init_deserializer_buf(&deserializer, buf, size) == 0) {
    ndpi_serialization_type kt, et;
    unsigned int guard = 0;

    while(guard++ < 1024 &&
          (et = ndpi_deserialize_get_item_type(&deserializer, &kt)) != ndpi_serialization_unknown) {

      /* Read the key */
      if(kt == ndpi_serialization_string) {
        ndpi_string ks;
        ndpi_deserialize_key_string(&deserializer, &ks);
      } else {
        u_int32_t k32;
        ndpi_deserialize_key_uint32(&deserializer, &k32);
      }

      /* Read the value according to its type */
      switch(et) {
      case ndpi_serialization_uint8:
      case ndpi_serialization_uint16:
      case ndpi_serialization_uint32: {
        u_int32_t v; ndpi_deserialize_value_uint32(&deserializer, &v); break;
      }
      case ndpi_serialization_uint64: {
        u_int64_t v; ndpi_deserialize_value_uint64(&deserializer, &v); break;
      }
      case ndpi_serialization_int8:
      case ndpi_serialization_int16:
      case ndpi_serialization_int32: {
        int32_t v; ndpi_deserialize_value_int32(&deserializer, &v); break;
      }
      case ndpi_serialization_int64: {
        int64_t v; ndpi_deserialize_value_int64(&deserializer, &v); break;
      }
      case ndpi_serialization_float: {
        float v; ndpi_deserialize_value_float(&deserializer, &v); break;
      }
      case ndpi_serialization_string:
      case ndpi_serialization_start_of_block:
      case ndpi_serialization_start_of_list: {
        ndpi_string vs; ndpi_deserialize_value_string(&deserializer, &vs); break;
      }
      default:
        break;
      }

      rc = ndpi_deserialize_next(&deserializer);
      if(rc <= 0)
        break;
    }
  }

  free(buf);

  return 0;
}
