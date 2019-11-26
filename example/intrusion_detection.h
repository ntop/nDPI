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