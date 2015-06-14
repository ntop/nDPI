/*
 * rndpi - a C library for deep packet inspection on top of nDPI
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Single-process, single-handle packet sniffer for pcap-aware network interfaces
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
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <signal.h>
#include <libgen.h>
#include <getopt.h>


#include <net/ethernet.h>
#include <netinet/ip.h>

/* Packet Capture Library */
#include <pcap.h>


/* rnDPI headers */
#include "rndpi.h"


#define DEFAULT_SNAPLEN   1518     /* default max length saved portion of each pkt */
#define DEFAULT_TIMEOUT   0        /* default read timeout                         */
#define DEFAULT_PACKETS   0        /* default # of packets to capture              */


/* Package info */
static char _NAME_    [] = "Single-process, single-handle deep packet analyzer for pcap-aware network interfaces";
static char _VERSION_ [] = "0.0.1";
static char _AUTHOR_  [] = "R. Carbone <rocco@tecsiel.it>";



/* Return an indication if the packet is Ethernet */
static bool is_ethernet (uint8_t * pkt, uint16_t len)
{
  return len >= sizeof (struct ether_header) + sizeof (struct iphdr);
}


/* Return an indication if the packet is IPv4 */
static bool is_ipv4 (void * pkt, uint16_t len)
{
  /* Cast the packet pointer to one that can be indexed */
  struct ether_header * eth = pkt;

  return is_ethernet (pkt, len) && ntohs (eth -> ether_type) == ETHERTYPE_IP;
}


/* Return an indication if the packet is UDP or TCP */
static bool is_udp_or_tcp_over_ipv4 (void * pkt, uint16_t len)
{
  /* Cast the packet pointer to one that can be indexed */
  struct iphdr * ipv4 = pkt + sizeof (struct ether_header);

  return is_ipv4 (pkt, len) && (ipv4 -> protocol == IPPROTO_UDP || ipv4 -> protocol == IPPROTO_TCP);
}


/* What should be done on interrupt */
static void on_interrupt (int sig)
{
  printf ("\n");
  printf ("Caught signal %d. Exiting ...\n", sig);
  exit (0);
}


/* Return the full qualified hostname */
static char * fqname (void)
{
  struct utsname machine;
  struct hostent * h;
  struct sockaddr_in in;

  uname (& machine);

  /* Attempt to resolv hostname to get the internet address */
  h = gethostbyname (machine . nodename);
  if (h)
    memcpy (& in . sin_addr, h -> h_addr_list [0], h -> h_length);
  else
    in . sin_addr . s_addr = inet_addr (machine . nodename);

  /* Back to the full qualified domain address */
  h = gethostbyaddr ((char *) & in . sin_addr, sizeof (struct in_addr), AF_INET);

  return ! h || ! h -> h_name ? inet_ntoa (in . sin_addr) : h -> h_name;
}


/* Announce to the world! */
static void helloworld (char * prog)
{
  time_t now = time (0);

  printf ("This is %s v. %s (%s %s) - %s\n", prog, _VERSION_, __DATE__, __TIME__, _AUTHOR_);
  printf ("started %24.24s on %s\n", ctime (& now), fqname ());
  printf ("\n");
}


/* Display version information */
static void version (char * prog)
{
  printf ("%s version %s built on %s %s\n", prog, _VERSION_, __DATE__, __TIME__);
}


/* How to use this program */
static void usage (char * progname)
{
  printf ("%s v. %s, %s\n", progname, _VERSION_, _NAME_);
  printf ("\n");

  printf ("Usage: %s [options]\n", progname);

  printf ("   -h             show usage and exit\n");
  printf ("   -v             show version and exit\n");

  printf ("   -i interface   use 'interface' for packet capture\n");
  printf ("   -s len         snapshot length. default %u\n", DEFAULT_SNAPLEN);

  printf ("   -c count       # of packets to capture. default %u - 0 unlimited\n", DEFAULT_PACKETS);
  printf ("   -t timeout     pcap read timeout in msecs. default %u\n", DEFAULT_TIMEOUT);
}


/*
 * Deep Packet Inspection over rnDPI
 *
 * 1. Open a network interface to obtain pcap-handle
 * 2. Capture 'n' packets
 * 3. Print global statistics information
 */
int main (int argc, char * argv [])
{
  char * progname  = basename (argv [0]);  /* notice program name */
  char * interface = NULL;                 /* interface name      */
  unsigned snaplen = DEFAULT_SNAPLEN;
  bool promiscuous = true;
   unsigned timeout = DEFAULT_TIMEOUT;      /* read timeout        */
  bool quiet       = false;

  /* How many packets */
  unsigned long maxcount = DEFAULT_PACKETS;
  unsigned long captured = 0;

  char ebuf [PCAP_ERRBUF_SIZE];
  pcap_t * pcap;
  int dlt;
  rndpi_t * rndpi;
  int option;

  /* Set unbuffered stdout */
  setvbuf (stdout, NULL, _IONBF, 0);

  /* Parse command-line options */
#define OPTSTRING "hvqi:s:t:c:"
  while ((option = getopt (argc, argv, OPTSTRING)) != -1)
    {
      switch (option)
	{
	default: return 1;

	  /* Miscellanea */
	case 'h': usage (progname);         return 0;
        case 'v': version (progname);       return 0;
	case 'q': quiet = 1;                break;

	  /* Network interfaces */
	case 'i': interface = optarg;       break;
	case 's': snaplen  = atoi (optarg); break;
	case 't': timeout  = atoi (optarg); break;

	  /* Application Limits */
	case 'c': maxcount = atoi (optarg); break;
	}
    }

  /* Find a suitable interface, if you don't have one */
  if (! interface && ! (interface = pcap_lookupdev (ebuf)))
    {
      if (! quiet)
	printf ("%s: no suitable interface found, please specify one with -i\n", progname);
      return 1;
    }

  /* Check for permissions */
  if ((getuid () && geteuid ()) || setuid (0))
    {
      if (! quiet)
	printf ("%s: sorry, you must be root in order to run this program\n", progname);
      return 1;
    }

  /* You are welcome! */
  helloworld (progname);

  /* Install signal handlers */
  signal (SIGPIPE, SIG_IGN);              /* Ignore writes to connections that have been closed at the other end */
  signal (SIGINT,  on_interrupt);         /* ^C */
  signal (SIGQUIT, on_interrupt);         /* quit */
  signal (SIGTERM, on_interrupt);         /* terminate */

  /* Open the interface for packet capturing */
  if (! (pcap = pcap_open_live (interface, snaplen, promiscuous, timeout, ebuf)))
    {
      if (! quiet)
	printf ("%s: cannot open interface '%s' [error '%s']\n", progname, interface, ebuf);
      return 1;
    }
  else
    {
      dlt = pcap_datalink (pcap);
      if (dlt != DLT_EN10MB)
	{
	  if (! quiet)
	    printf ("%s: unsupported data link type '%s' for interface %s\n", progname, pcap_datalink_val_to_name (dlt), interface);
	  pcap_close (pcap);
	  return 1;
	}
    }

  /* Initialize rnDPI */
  rndpi = rndpi_alloc ();

  /* Announce */
  if (! quiet)
    printf ("%s: listening on %s, link-type %s (%s), capture size %u bytes\n",
	    progname, interface, pcap_datalink_val_to_name (dlt), pcap_datalink_val_to_description (dlt), snaplen);

  while (! maxcount || captured < maxcount)
    {
      struct pcap_pkthdr hdr;
      void * pkt;

      /* Get a packet from the interface */
      if ((pkt = (void *) pcap_next (pcap, & hdr)))
	{
	  /* rnDPI decoding is only applied to IPv4 packets carrying UDP or TCP */
	  if (is_udp_or_tcp_over_ipv4 (pkt, hdr . caplen))
	    {
	      /* Attempt to guess the IPv4 packet over the handle */
	      int deep = rndpi_deep_ipv4_pkt (rndpi,
					      pkt + sizeof (struct ether_header),
					      hdr . caplen - sizeof (struct ether_header));
	      if (deep > 0)
		printf ("%s: %u %s\n", progname, deep, rndpi_protocol_name (deep));
	    }
	  captured ++;
	}
    }

  /* Terminate rnDPI */
  rndpi_free (rndpi);

  /* Close the interface */
  pcap_close (pcap);

  return 0;
}
