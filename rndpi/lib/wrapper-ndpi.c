/*
 * rndpi - a C library for deep packet inspection on top of nDPI
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Wrapper to nDPI functions
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
 *
 */


/* System headers */
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>


/* nDPI headers */
#include "ndpi_api.h"


/* Private memory allocator/deallocator/logging functions */
static void * malloc_ndpi (unsigned long size) { return calloc (1, size); }
static void free_ndpi (void * mem)             { if (mem) free (mem);     }
static void log_ndpi (uint32_t protocol, void * id, ndpi_log_level_t log_level, const char * format, ...) { }


/* Initialize nDPI library */
void * ndpi_init (void)
{
  struct ndpi_detection_module_struct * dpi = ndpi_init_detection_module (1e6, malloc_ndpi, free_ndpi, log_ndpi);

  /* enable all protocols */
  NDPI_PROTOCOL_BITMASK all;
  NDPI_BITMASK_SET_ALL (all);
  ndpi_set_protocol_detection_bitmask2 (dpi, & all);

  return dpi;
}


/* Terminate nDPI library */
void ndpi_term (void * dpi)
{
  if (dpi)
    ndpi_exit_detection_module ((struct ndpi_detection_module_struct *) dpi, ndpi_free);
}


/* Allocate memory to keep a flow */
void * ndpi_flow_alloc (void)
{
  return calloc (1, ndpi_detection_get_sizeof_ndpi_flow_struct ());
}


/* Free memory used to keep a flow */
void ndpi_flow_free (void * flow)
{
  if (flow)
    free (flow);
}


/* Process a packet and return the ID of the detected protocol (if any) */
uint16_t ndpi_ipv4_pkt (void * pkt, uint32_t len, void * dpi, void * flow)
{
  return ndpi_detection_process_packet (dpi, flow, (uint8_t *) pkt, len, 0, NULL, NULL);
}


/* ROCCO: Bind an IPv4 packet to a flow */
void ndpi_bind_ipv4_pkt (void * pkt, uint32_t len, void * f)
{
  /* Cast the packet pointer to one that can be indexed */
  struct iphdr * ipv4 = pkt;
  struct ndpi_flow_struct * flow = f;

  flow -> packet . iph = (struct ndpi_iphdr *) pkt;

  switch (ipv4 -> protocol)
    {
    case IPPROTO_UDP:
      flow -> packet . udp                = pkt + sizeof (struct iphdr);
      flow -> packet . payload            = pkt + sizeof (struct iphdr) + sizeof (struct udphdr);
      flow -> packet . payload_packet_len = len - (sizeof (struct iphdr) + sizeof (struct udphdr));
      break;

    case IPPROTO_TCP:
      flow -> packet . tcp                = pkt + sizeof (struct iphdr);
      flow -> packet . payload            = pkt + sizeof (struct iphdr) + sizeof (struct tcphdr);
      flow -> packet . payload_packet_len = len - (sizeof (struct iphdr) + sizeof (struct tcphdr));
      break;
    }
}


/* ROCCO: Please insert a brief description here */
unsigned ndpi_protocol (void * f)
{
  struct ndpi_flow_struct * flow = f;
  if (flow -> packet . detected_protocol_stack [0] == NDPI_PROTOCOL_UNKNOWN)
    return 0;
  else
    return flow -> packet . detected_protocol_stack [0];
}
