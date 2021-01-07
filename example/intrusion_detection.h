/*
 * intrusion_detection.h
 *
 * Copyright (C) 2011-21 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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

#ifndef _INTRUSION_DETECTION_H_
#define _INTRUSION_DETECTION_H_

/*
  Code to detect attacks reported in

  https://www.unb.ca/cic/datasets/ids-2017.html
  https://www.unb.ca/cic/datasets/ids-2018.html
*/

#include <stdio.h>
#include <stdlib.h>
#include "reader_util.h"
#include "ndpi_api.h"

typedef struct norm_values{
  double upper_bound;
  double lower_bound;
  double weight;
  double value;
  double norm_value;
}ndpi_norm_value;

double normalize(ndpi_norm_value* tresholds);

double get_flow_score(ndpi_norm_value* scores, int n_metrics);

/* ********************************** */

double Ddos_score(struct ndpi_flow_info* flow);

double Dos_goldeneye_score(struct ndpi_flow_info* flow);

double Dos_hulk_score(struct ndpi_flow_info* flow);

double Dos_slow_score(struct ndpi_flow_info* flow);

double Ftp_patator_score(struct ndpi_flow_info* flow);

double Hearthbleed_score(struct ndpi_flow_info* flow);

double Infiltration_score(struct ndpi_flow_info* flow);

double Ssh_patator_score(struct ndpi_flow_info* flow);

#endif /* _INTRUSION_DETECTION_H_ */
