/*
 * metric_anomaly.c
 *
 * Copyright (C) 2011-22 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <getopt.h>
#include "ndpi_api.h"

#define  DEFAULT_ALPHA   0.5
#define  DEFAULT_RO      0.05

/* *************************************************** */

static void help() {
  printf("Usage: metric_anomaly [-Q][-v][-z][-a <alpha>][-q] -d <database> -q <query>\n"
	 "-a             | Set alpha. Valid range >0 .. <1. Default %.2f\n"
	 "-Q             | Quick output (only anomalies are reported)\n"
	 "-d <database>  | InfluxDB database name\n"
	 "-q <query>     | InfluxQL query\n"
	 "-v             | Verbose\n"
	 "-z             | Bottom metric value set to zero\n"
	 ,
	 DEFAULT_ALPHA);

  printf("\n\nExample: metric_anomaly -d ntopng -q \"%s\"\n",
	 "SELECT mean(\"cpu0\") FROM \"cpu_load\" WHERE time > 1648634807000000000 GROUP BY time(60s) fill(previous)");
  exit(0);
}

/* *************************************************** */

int main(int argc, char *argv[]) {
  char *database = NULL, *query = NULL, cmd[512], buf[256];
  u_int i, j, first = 1, quick_mode = 0, verbose = 0;
  struct ndpi_ses_struct ses;
  float alpha, ro;
  char c;
  FILE *fd;
  bool go_below_zero = true;
  
  /* Defaults */
  alpha   = DEFAULT_ALPHA;
  ro      = DEFAULT_RO;
  
  while((c = getopt(argc, argv, "a:Qd:q:vz")) != '?') {
    if(c == -1) break;

    switch(c) {
    case 'a':
      {
	float f = atof(optarg);

	if((f > 0) && (f < 1))
	  alpha = f;
	else
	  printf("Discarding -a: valid range is >0 .. <1\n");
      }
      break;

    case 'Q':
      quick_mode = 1;
      break;

    case 'd':
      database = optarg;
      break;

    case 'q':
      query = optarg;
      break;

    case 'v':
      verbose = 1;
      break;

    case 'z':
      go_below_zero = false;
      break;

    default:
      help();
      break;
    }
  }

  if((database == NULL) || (query == NULL))
    help();

  ndpi_snprintf(cmd, sizeof(cmd), "influx -database '%s' -precision s -execute '%s'", database, query);

  if(verbose) printf("%s\n", cmd);

  if ((fd = popen(cmd, "r")) == NULL) {
    printf("Unable to execute '%s'\n", cmd);
    return(-1);
  }

  ndpi_ses_init(&ses, alpha, ro);
  
  while(fgets(buf, sizeof(buf), fd) != NULL) {
    u_int32_t epoch;
    float value;
    double prediction, confidence_band;
    double lower, upper;
    int rc;
    bool is_anomaly;

    if(sscanf(buf, "%u %f", &epoch, &value) != 2)
      continue;

    // printf("->>> '%s'", buf);
      
    value *= 100; /* trick to avoid dealing with floats */
    rc = ndpi_ses_add_value(&ses, value, &prediction, &confidence_band);
    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(!go_below_zero) lower = ndpi_max(lower, 0), upper = ndpi_max(upper, 0);
    
    is_anomaly = ((rc == 0) || (confidence_band == 0) || ((value >= lower) && (value <= upper))) ? false : true;
    
    if(verbose || is_anomaly) {
      const time_t _t = epoch;
      struct tm *t_info = localtime((const time_t*)&_t);

      strftime(buf, sizeof(buf), "%d/%b/%Y %H:%M:%S", t_info);
      
      if(quick_mode) {
	if(is_anomaly) {
	  printf("%u [%s]\n", epoch, buf);
	}
      } else {       	
	if(first) {
	  first = 0;
	  printf("%s                       %s\t%s    %s           %s\t %s     [%s]\n",
		 "When", "Value", "Prediction", "Lower", "Upper", "Out", "Band");
	}
	
	printf("%s %12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f][rc: %d]\n",
	       buf, value/100., prediction/100., lower/100., upper/100., is_anomaly? "ANOMALY" : "OK",
	       confidence_band/100., rc);
      }
    }    
  }
  
  (void)pclose(fd);
  
  return(0);
}
