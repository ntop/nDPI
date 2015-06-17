/*
 * rndpi - a C library for deep packet inspection on top of nDPI
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * API implementation
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
 *
 */


/* Library headers */
#include "rndpi.h"
#include "private-rndpi.h"


/* =-=-=-=- Protocols -=-=-=-= */

/* Return # of protocols implemented */
unsigned rndpi_protocol_count (void)
{
  return ndpi_protocol_count ();
}


/* Return the protocol name */
char * rndpi_protocol_name (unsigned id)
{
  rndpi_protocol_t * p;

  if (id == RNDPI_PROTOCOL_UNKNOWN)
    return "Unknown";

  p = ndpi_lookup_by_id (id);
  return p ? p -> name : NULL;
}


/* Return the protocol id */
int rndpi_protocol_id (char * name)
{
  rndpi_protocol_t * p = ndpi_lookup_by_name (name);
  return p ? p -> id : -1;
}


/* Return the protocol description */
char * rndpi_protocol_description (unsigned id)
{
  rndpi_protocol_t * p = ndpi_lookup_by_id (id);
  return p && p -> description ? p -> description : "To be defined";
}


/* Return all protocol names in a NULL terminated array */
char ** rndpi_protocol_names (void)
{
  return ndpi_protocol_names ();
}


/* Return an indication if protocol is implemented */
bool rndpi_protocol_is_implemented (unsigned id)
{
  rndpi_protocol_t * p = ndpi_lookup_by_id (id);
  return p && p ->  bless;
}


/* Return only not yet implementesd protocols in a NULL terminated array */
char ** rndpi_protocol_not_implemented (void)
{
  return ndpi_protocol_not_implemented ();
}


#if defined(ROCCO)

/* Bless an IPv4 packet */
unsigned rndpi_bless_ipv4_pkt (void * pkt, uint32_t len)
{
  unsigned i;

  for (i = 0; i < ndpi_protocol_count (); i ++)
    {
      /* Initialize nDPI library */
      void * ndpi = ndpi_init ();

      if (all_protocols [i] . guess)
	{
	  uint16_t deep;

	  /* Alloc flow */
	  void * flow = ndpi_flow_alloc ();

	  /* Bind the packet to the flow */
	  ndpi_bind_ipv4_packet (pkt, len, flow);

	  printf ("Trying %s ...\n", all_protocols [i] . name);

	  (* all_protocols [i] . guess) (ndpi, flow);

	  deep = ndpi_protocol (flow);
	  if (deep)
	    ;

	  /* Free flow */
	  ndpi_flow_free (free);

	}

      /* Terminate nDPI library */
      ndpi_term (ndpi);
    }

  return RNDPI_PROTOCOL_UNKNOWN;
}

#else

/* Bless an IPv4 packet */
int rndpi_bless_ipv4_pkt (void * ipv4, uint32_t len)
{
  void * ndpi;
  void * flow;

  if (! ipv4 || len <= sizeof (struct iphdr))
    return -1;

  /* Initialize nDPI library */
  ndpi = ndpi_init ();
  flow = ndpi_flow_alloc ();         /* A flow is alwyas required by the underlaying nDPI functions */

  /* Attempt to bless the IPv4 packet */
  uint16_t deep = ndpi_ipv4_pkt (ipv4, len, ndpi, flow);

  /* Free flow and terminate nDPI library */
  ndpi_flow_free (flow);
  ndpi_term (ndpi);

  return deep;
}

#endif /* ROCCO */


/* Get rnDPI handle */
rndpi_t * rndpi_alloc (void)
{
  rndpi_t * rndpi = calloc (1, sizeof (struct rndpi));
  rndpi -> handle = ndpi_init ();                      /* Get nDPI handle */
  rndpi -> flow   = ndpi_flow_alloc ();                /* Get nDPI flow   */

  return rndpi;
}


/* Release rnDPI handle */
void rndpi_free (rndpi_t * rndpi)
{
  if (! rndpi)
    return;

  ndpi_flow_free (rndpi -> flow);                      /* Release nDPI flow   */
  ndpi_term (rndpi -> handle);                         /* Release nDPI handle */
  free (rndpi);
}


/* Deep an IPv4 packet over a handle */
int rndpi_deep_ipv4_pkt (rndpi_t * rndpi, void * ipv4, uint32_t len)
{
  uint16_t deep;

  if (! rndpi || ! ipv4 || len <= sizeof (struct iphdr))
    return -1;

  /* Attempt to bless the IPv4 packet */
  deep = ndpi_ipv4_pkt (ipv4, len, rndpi -> handle, rndpi -> flow);

  /*
   * Warning:
   *  Identifiers need to be mapped due to different position of UNKNOWN in the tables
   */
  if (! deep)
    deep = RNDPI_PROTOCOL_UNKNOWN;
  else
    deep = deep - 1;

  return deep;
}
