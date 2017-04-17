/*
 * rndpi - a C library for deep packet inspection on top of nDPI
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Does nothing but get and release a rnDPI handle
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
 *
 */


/* library headers */
#include "rndpi.h"


/* Does nothing. Run it with valgrind to check for memory leaks */
int main (int argc, char * argv [])
{
  rndpi_free (rndpi_alloc ());

  return 0;
}
