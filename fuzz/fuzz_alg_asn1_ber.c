#include "ndpi_api.h"

#include <assert.h>

#define MAX_DEPTH 16

/* Decode all the TLVs in the buffer, recursing into the constructed ones */
static void walk_tlvs(const u_int8_t *buf, u_int32_t buf_len, int depth) {
  struct ndpi_asn1_ber_tlv tlv;
  int32_t value;
  int used;

  while(buf_len > 0) {
    used = ndpi_asn1_ber_decode_tlv(buf, buf_len, &tlv);
    if(used < 0)
      return;

    /* The whole TLV must be inside the buffer, with the value at its end */
    assert(used >= 2 && (u_int32_t)used <= buf_len);
    assert(tlv.value > buf && tlv.value + tlv.length == buf + used);

    assert(ndpi_asn1_ber_decode_single_tlv(buf, used, &tlv) == 0);

    if(tlv.tag == 0x02 /* INTEGER */)
      ndpi_asn1_ber_decode_int(buf, used, &value);

    if((tlv.tag & 0x20) /* Constructed */ && depth < MAX_DEPTH)
      walk_tlvs(tlv.value, tlv.length, depth + 1);

    buf += used;
    buf_len -= used;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ndpi_asn1_ber_tlv tlv;
  int32_t value;
  int64_t len;
  u_int16_t value_len;
  u_int32_t length;
  u_int8_t tag;
  int hdr_len;

  /* No memory allocations involved */

  len = ndpi_asn1_ber_decode_length(data, (int)size, &value_len);
  if(len >= 0)
    assert(len <= 0xFFFFFFFF && value_len >= 1 && value_len <= 5 && value_len <= size);

  hdr_len = ndpi_asn1_ber_decode_header(data, size, &tag, &length);
  if(hdr_len >= 0)
    assert(hdr_len >= 2 && hdr_len <= 6 && (size_t)hdr_len <= size);

  ndpi_asn1_ber_decode_single_tlv(data, size, &tlv);
  ndpi_asn1_ber_decode_int(data, size, &value);

  walk_tlvs(data, size, 0);

  return 0;
}
