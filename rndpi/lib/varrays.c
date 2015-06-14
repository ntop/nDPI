/*
 * rndpi - a C library for deep packet inspection on top of nDPI
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Utilities to handle array of pointers to void objects
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
 *
 */


/* System headers */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>


/* Library headers */
#include "rlibc.h"


/* Limits for static buffers in itoa() */
#define ITEMS 10     /* rows */
#define SIZE  16     /* cols */

static int alphabetically (const void * _a, const void * _b)
{
  return strcmp (* (char **) _a, * (char **) _b);
}


/* Lookup by reference for an item into the NULL terminated array */
static int valookup (void * argv [], void * item)
{
  int found = 0;

  while (argv && * argv)
    if (* argv ++ == item)
      return found;
    else
      found ++;

  return -1;
}


/* Lookup for a name in a table */
static bool exists (char * argv [], char * name)
{
  while (name && argv && * argv)
    if (! strcmp (* argv ++, name))
      return true;
  return false;
}


/* Integer to Ascii */
char * itoa (int n)
{
  static char text [ITEMS] [SIZE];
  static int i = 0;

  char * s = text [i ++ % ITEMS];
  sprintf (s, "%d", n);
  return s;
}


/* Return the # of items in the NULL terminated array */
unsigned valen (void * argv [])
{
  unsigned argc = 0; while (argv && * argv ++) argc ++; return argc;
}


/* Add an item to the NULL terminated array */
void ** vamore (void * argv [], void * item)
{
  if (item)
    {
      unsigned argc = valen (argv);
      argv = realloc (argv, (1 + argc + 1) * sizeof (void **));
      if (! argv)
	return NULL;
      argv [argc ++] = item;
      argv [argc]    = NULL;         /* make the array NULL terminated */
    }
  return argv;
}


/* Remove an item from the NULL terminated array */
void ** valess (void * argv [], void * item, void (* rmitem) (void *))
{
  unsigned argc = valen (argv);
  unsigned i;

  if ((i = valookup (argv, item)) != -1)
    {
      unsigned j;

    if (rmitem)
	rmitem (argv [i]);               /* free the descriptor */

      for (j = i; j < argc - 1; j ++)    /* move pointers back one position */
        argv [j] = argv [j + 1];
      argv [j] = NULL;                   /* terminate the array */

      if (argc > 1)
        argv = realloc (argv, argc * sizeof (void *));
      else
        free (argv);
    }

  return argc > 1 ? argv : NULL;
}


/* Cleanup the NULL terminated array */
void ** vacleanup (void * argv [], void (* rmitem) (void *))
{
  void ** a = argv;
  while (a && * a)
    {
      if (rmitem)
	rmitem (* a);
      a ++;
    }
  if (argv)
    free (argv);
  return NULL;
}


/* Duplicate the NULL terminated array */
void ** vadup (void * argv [])
{
  void ** dup = NULL;
  if (argv)
    while (* argv)
      dup = vamore (dup, * argv ++);

  return dup;
}


unsigned vadigits (unsigned n)
{
  return n < 10 ? 1 : 1 + vadigits (n / 10);
}


char * vafmt (void * argv [])
{
  static char fmt [10];
  sprintf (fmt, "%%%uu:", vadigits (valen (argv)));
  return fmt;
}


/* Evaluate the format to print a number of n digits left aligned */
char * valeft (unsigned n)
{
  static char fmt [10];
  if (n == 0)
    sprintf (fmt, "%%.0f");
  else
    sprintf (fmt, "%%-%u.0f", vadigits (n));
  return fmt;
}


/* Sort 'argv' */
void ** vasort (void * argv [], sf_t * cmpfunc)
{
  if (argv && cmpfunc)
    qsort (argv, valen (argv), sizeof (void *), cmpfunc);

  return argv;
}


/* Add an item to the array of arguments */
char ** argsadd (char * argv [], char * s)
{
  return s ? ((char **) vamore ((void **) argv, (void *) strdup (s))) : argv;
}


void argsfree (char * argv [])
{
  vacleanup ((void **) argv, free);
}


/* Add an item to a table (if not already in) */
char ** argsuniq (char * argv [], char * item)
{
  return exists (argv, item) ? argv : argsadd (argv, item);
}


/* Print the arguments in 'argc' rows (one argument for line) */
void argsrows (char * argv [])
{
  unsigned argc = 0;
  while (argv && * argv)
    printf ("%3d. \"%s\"\n", ++ argc, * argv ++);
}


char ** argssort (char * argv [])
{
  return (char **) vasort ((void **) argv, alphabetically);
}


/* Split a string into pieces */
char ** argssplit (char * str, char * sep)
{
  char ** argv = NULL;
  char * rest = NULL;
  char * param;
  char * data;
  char * m;

  if (! str || ! sep)
    return NULL;

  m = data = strdup (str);                  /* this is due strtok_r() modifies input buffer 'str' */

  param = strtok_r (data, sep, & rest);
  while (param)
    {
      /* Add current field to the array */
      argv = argsadd (argv, param);

      /* Process empty fields (add the separator) */
      if (rest && * rest == * sep)
	{
	  char * p = rest;
	  while (* p ++ == * sep)
	    argv = argsadd (argv, sep);
	}

      /* Next field */
      param = strtok_r (NULL, sep, & rest);
    }
  free (m);

  return argv;
}


/* Build a comma separated list of names */
char * build_names (char * argv [])
{
  char * names = NULL;
  while (argv && * argv)
    {
      if (! names)
	  names = strdup (* argv);
      else
	{
	  names = realloc (names, strlen (names) + strlen (* argv) + 1 + 1);
	  sprintf (names + strlen (names), "%c%s", ',', * argv);
	}
      argv ++;
    }
  return names;
}
