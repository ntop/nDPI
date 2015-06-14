/*
 * rndpi - a C library for deep packet inspection on top of nDPI
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Does nothing but try to link static library
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
 *
 */


/* Library headers */
#include "rndpi.h"


/*
 * The following statements have been written only to test
 * if a binary program can be generated at compile time.
 * They will be never executed, so there is no need to check about failures.
 */
int main (int argc, char * argv [])
{
  printf ("This program does nothing, but it only tests if link works at compile time. Bye bye!\n");

  if (0)
    {
      /* Protocols */
      rndpi_protocol_count ();                /* Return # of protocols implemented      */
      rndpi_protocol_name (0);                /* Return the protocol name               */
      rndpi_protocol_id (NULL);               /* Return the protocol id                 */
      rndpi_protocol_description (0);         /* Return the protocol description        */
      rndpi_protocol_names ();                /* Return all protocol names (array)      */
      rndpi_protocol_is_implemented (0);      /* Return if protocol is implemented      */
      rndpi_protocol_not_implemented ();      /* Return all protocols not implemented   */

      rndpi_protocol_list_alloc ();           /* Return all protocol names (list)       */
      rndpi_protocol_list_print (NULL);       /* Print all items in the protocol list   */
      rndpi_protocol_list_free (NULL);        /* Free all items in the protocol list    */

      /* Handles */
      rndpi_alloc ();
      rndpi_free (NULL);

      /* Deep inspection */
      rndpi_bless_ipv4_pkt (NULL, 0);         /* Bless an IPv4 packet                   */
      rndpi_deep_ipv4_pkt (NULL, NULL, 0);    /* Deep an IPv4 packet                    */
    }

  return 0;
}
