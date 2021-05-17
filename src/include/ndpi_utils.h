

#ifndef __NDPI_UTILS_H__
#define __NDPI_UTILS_H__

#include "ndpi_define.h"

#define MYDBG(m, ...) \
	printf(" DBG[%s:%s:%u]: \t" m "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);

// #define NDPI_ENABLE_DEBUG_POINTER_MESSAGES
// #define NDPI_ENABLE_DEBUG_INFO_MESSAGES
// #define NDPI_ENABLE_DEBUG_TRACE_MESSAGES

extern void printRawData(const uint8_t *ptr, size_t len);
//extern uint8_t add_segment_to_buffer( struct ndpi_flow_struct *flow, struct ndpi_tcphdr const * tcph, uint32_t waited);
//extern uint8_t check_for_sequence( struct ndpi_flow_struct *flow, struct ndpi_tcphdr const * tcph);

#endif
