#include <stddef.h>
#include <stdio.h>

#include "ndpi_typedefs.h"

#define PRINT_MEMBER(type, member) \
  printf("%-40s offset=%4zu size=%4zu cacheline=%zu\n", \
         #member, offsetof(type, member), sizeof(((type *)0)->member), \
         offsetof(type, member) / 64)

int main(void) {
  typedef struct ndpi_flow_metadata_struct metadata_t;
  typedef struct ndpi_flow_struct flow_t;

  printf("sizeof(struct ndpi_flow_metadata_struct) = %zu\n",
         sizeof(metadata_t));
  printf("alignof(struct ndpi_flow_metadata_struct) = %zu\n",
         _Alignof(metadata_t));
  printf("sizeof(struct ndpi_flow_struct) = %zu\n",
         sizeof(flow_t));
  printf("alignof(struct ndpi_flow_struct) = %zu\n",
         _Alignof(flow_t));

  PRINT_MEMBER(metadata_t, l4);
  PRINT_MEMBER(metadata_t, flow_multimedia_types);
  PRINT_MEMBER(metadata_t, entropy);
  PRINT_MEMBER(metadata_t, ndpi);
  PRINT_MEMBER(metadata_t, http);
  PRINT_MEMBER(metadata_t, kerberos_buf);
  PRINT_MEMBER(metadata_t, protos);
  PRINT_MEMBER(metadata_t, openvpn);
  PRINT_MEMBER(metadata_t, custom);
  PRINT_MEMBER(metadata_t, monit);
  PRINT_MEMBER(metadata_t, stun);
  PRINT_MEMBER(metadata_t, rtp);

  return 0;
}
