

#ifndef __NDPI_UTILS_H__
#define __NDPI_UTILS_H__

#include "ndpi_define.h"

#define MYDBG(m, ...) \
	printf(" DBG[%s:%s:%u]: \t" m "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);

// #define NDPI_ENABLE_DEBUG_POINTER_MESSAGES
// #define NDPI_ENABLE_DEBUG_INFO_MESSAGES
// #define NDPI_ENABLE_DEBUG_TRACE_MESSAGES

#ifdef FRAG_MAN
#ifdef NDPI_ENABLE_DEBUG_POINTER_MESSAGES
#define DBGPOINTER(m, args...) MYDBG(m, ##args)
#else
#define DBGPOINTER(m, args...) 
#endif

#ifdef NDPI_ENABLE_DEBUG_INFO_MESSAGES
#define DBGINFO(m, args...) MYDBG(m, ##args)
#else
#define DBGINFO(m, args...) 
#endif

#ifdef NDPI_ENABLE_DEBUG_TRACE_MESSAGES
#define DBGTRACER(m, args...) MYDBG(m, ##args)
#else
#define DBGTRACER(m, args...) 
#endif

// FRAGMENTATION
typedef struct {
    uint32_t offset;
    size_t len;
    void *data;    
} fragment_t;

typedef struct fragment_wrapper {
     uint16_t id;
     uint8_t l4_protocol;
     uint32_t initial_offset;
     uint16_t ct_frag;
     char   *flow_label;    // IP6
     char gap[200];
     fragment_t **fragments_list;
} fragments_wrapper_t;

typedef struct fragments_buffer  {
    u_int8_t *buffer;
    u_int buffer_len, buffer_used;
} fragments_buffer_t;

// SORTING 
typedef struct  {
	int sort_value;
	int item_index;
} sorter_index_item_t;


/* ***************************************************** */

extern void ins_sort_array(sorter_index_item_t arr[], int len);
extern void shell_sort_array(sorter_index_item_t arr[], int len);
extern void free_fragment(fragments_wrapper_t *frag);

#endif


extern void printRawData(const uint8_t *ptr, size_t len);
//extern uint8_t add_segment_to_buffer( struct ndpi_flow_struct *flow, struct ndpi_tcphdr const * tcph, uint32_t waited);
//extern uint8_t check_for_sequence( struct ndpi_flow_struct *flow, struct ndpi_tcphdr const * tcph);

#endif
