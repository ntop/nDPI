/*
 * rndpi - a C library for deep packet inspection on top of nDPI
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Public API
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
 *
 */


#ifndef _RNDPI_H_
#define _RNDPI_H_


/* System headers */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>


/* System headers for Internet Protocols Addressing definitions */
#include <netinet/ether.h>
#include <arpa/inet.h>


/* System headers for Internet Protocols Packets definitions */
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>


/* Library headers */
#include "rlibc.h"


/*
 * Public Constants
 */


/*
 * Public Datatypes. The internals of the structures are all private
 */

typedef enum rndpi_id rndpi_id_t;
typedef struct rndpi_protocol rndpi_protocol_t;              /* supported protocols */
typedef struct rndpi rndpi_t;                                /* handles             */


/* Public functions */

#ifdef __cplusplus
extern "C" {
#endif


/* Protocols */
unsigned rndpi_protocol_count (void);                                  /* Return # of protocols implemented    */
char * rndpi_protocol_name (unsigned id);                              /* Return the protocol name             */
int rndpi_protocol_id (char * name);                                   /* Return the protocol id               */
char * rndpi_protocol_description (unsigned id);                       /* Return the protocol description      */
char ** rndpi_protocol_names (void);                                   /* Return all protocol names (array)    */
bool rndpi_protocol_is_implemented (unsigned id);                      /* Return if protocol is implemented    */
char ** rndpi_protocol_not_implemented (void);                         /* Return all protocols not implemented */


/* Handles */
rndpi_t * rndpi_alloc (void);                                          /* Get a rnDPI handle                   */
void rndpi_free (rndpi_t * rndpi);                                     /* Release a rnDPI handle               */


/* Deep inspection */
int rndpi_bless_ipv4_pkt (void * pkt, uint32_t len);                   /* Bless an IPv4 packet                 */
int rndpi_deep_ipv4_pkt (rndpi_t * rndpi, void * pkt, uint32_t len);   /* Deep an IPv4 packet (handle)         */


#ifdef __cplusplus
}
#endif


#endif /* _RNDPI_H_ */
