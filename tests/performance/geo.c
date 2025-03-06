#include <ndpi_api.h>
#include <stdio.h>

int main()
{
    struct ndpi_detection_module_struct *ndpi_info_mod;
    int rc;

    ndpi_info_mod = ndpi_init_detection_module(NULL);
    if (ndpi_info_mod == NULL)
        return 1;

    ndpi_finalize_initialization(ndpi_info_mod);

    rc = ndpi_load_geoip(ndpi_info_mod, "GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb");
    if(rc != 0) {
        fprintf(stderr, "Error loading db files: %d\n", rc);
        return 1;
    }

    char country[50], continent[50], city[50], aso[50];
    u_int32_t asn;

    char *ips[] = {"24.124.1.8", "8.8.8.8", "161.148.164.31", "184.74.73.88"};

    for (u_int8_t i = 0; i < sizeof(ips)/sizeof(ips[0]); i++) {
        ndpi_get_geoip_country_continent_city(ndpi_info_mod, ips[i], country, sizeof(country), continent, sizeof(continent), city, sizeof(city));
        ndpi_get_geoip_aso(ndpi_info_mod, ips[i], aso, sizeof(aso));
        ndpi_get_geoip_asn(ndpi_info_mod, ips[i], &asn);
        printf("%u\n\tCountry: %s\n\tContinent: %s\n\tCity: %s\n\tASN: %u\n\tASO: %s\n\n", i + 1, country, continent, city, asn, aso);
    }

    ndpi_exit_detection_module(ndpi_info_mod);

    return 0;
}
