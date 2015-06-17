/*
 * rndpi - a C library for deep packet inspection on top of nDPI
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Example of usage of protocols related functions
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
 *
 */


/* System headers */
#include <libgen.h>
#include <getopt.h>


/* library headers */
#include "rndpi.h"


enum
{
  RNDPI_COUNT,
  RNDPI_NAME,
  RNDPI_ID,
  RNDPI_DESCRIPTION,
  RNDPI_NAMES,
  RNDPI_IMPLEMENTED,
  RNDPI_NOT_IMPLEMENTED,
};


static void usage (void)
{
  printf ("Option\n");

  printf (" -h   display this message and exit\n");
  printf (" -n   display all supported protocol names\n");
  printf (" -i   display all supported protocol ids\n");
  printf (" -d   display all supported protocol descriptions\n");
  printf (" -s   display all supported protocol names and ids\n");
  printf (" -a   display all supported protocol availability\n");
  printf (" -x   display only protocol names not yet implemented\n");
}


/* List all supported protocols */
int main (int argc, char * argv [])
{
  unsigned n = rndpi_protocol_count ();
  unsigned doit = RNDPI_COUNT;
  unsigned i;
  char ** names;
  int option;

#define OPTSTRING "hnidsax"
  while ((option = getopt (argc, argv, OPTSTRING)) != -1)
    {
      switch (option)
        {
	default:  usage (); return 1;
	case 'h': usage (); return 0;

	case 'n': doit = RNDPI_NAME;            break;
	case 'i': doit = RNDPI_ID;              break;
	case 'd': doit = RNDPI_DESCRIPTION;     break;
	case 's': doit = RNDPI_NAMES;           break;
	case 'a': doit = RNDPI_IMPLEMENTED;     break;
	case 'x': doit = RNDPI_NOT_IMPLEMENTED; break;
	}
    }

  switch (doit)
    {
      /* Unit test for function rndpi_protocol_count() */
    case RNDPI_COUNT:
      printf ("Number of supported protocols %u\n", rndpi_protocol_count ());
      break;

      /* Unit test for function rndpi_protocol_name() */
    case RNDPI_NAME:
      printf ("Name\n");
      for (i = 0; i < n; i ++)
	printf ("%3u - %s\n", i, rndpi_protocol_name (i));
      break;

      /* Unit test for function rndpi_protocol_id() */
    case RNDPI_ID:
      printf ("Id\n");
      for (i = 0; i < n; i ++)
	printf ("%3u: %3u - %s\n", i, rndpi_protocol_id (rndpi_protocol_name (i)), rndpi_protocol_name (i));
      break;

      /* Unit test for function rndpi_protocol_description() */
    case RNDPI_DESCRIPTION:
      printf ("Description\n");
      for (i = 0; i < n; i ++)
	printf ("%3u: %-41.41s - %s\n", i, rndpi_protocol_name (i), rndpi_protocol_description (i));
      break;

      /* Unit test for function rndpi_protocol_names() */
    case RNDPI_NAMES:
      printf ("Names\n");
      i = 0;
      names = rndpi_protocol_names ();
      while (names [i])
	{
	  printf ("[%3u] %s\n", i, names [i]);
	  i ++;
	}
      argsfree (names);
      break;

      /* Unit test for function rndpi_protocol_is_implemented() */
    case RNDPI_IMPLEMENTED:
      for (i = 0; i < n; i ++)
	printf ("%3u: %-41.41s - %s\n", i, rndpi_protocol_name (i), rndpi_protocol_is_implemented (i) ? "Yes" : "No");
      break;

      /* Unit test for function rndpi_protocol_not_implemented() */
    case RNDPI_NOT_IMPLEMENTED:
      printf ("Not yet implemented protocols\n");
      i = 0;
      names = rndpi_protocol_not_implemented ();
      while (names [i])
	{
	  printf ("%3u: %s\n", i + 1, names [i]);
	  i ++;
	}
      argsfree (names);
      break;
    }

  return 0;
}
