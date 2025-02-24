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

    char country[50], continent[50], city[50];

    ndpi_get_geoip_country_continent_city(ndpi_info_mod, "24.124.1.8", country, sizeof(country), continent, sizeof(continent), city, sizeof(city));
    printf("1\n\tCountry: %s\n\tContinent: %s\n\tCity: %s\n", country, continent, city);
    ndpi_get_geoip_country_continent_city(ndpi_info_mod, "8.8.8.8", country, sizeof(country), continent, sizeof(continent), city, sizeof(city));
    printf("2\n\tCountry: %s\n\tContinent: %s\n\tCity: %s\n", country, continent, city);
    ndpi_get_geoip_country_continent_city(ndpi_info_mod, "161.148.164.31", country, sizeof(country), continent, sizeof(continent), city, sizeof(city));
    printf("3\n\tCountry: %s\n\tContinent: %s\n\tCity: %s\n", country, continent, city);
    ndpi_get_geoip_country_continent_city(ndpi_info_mod, "184.74.73.88", country, sizeof(country), continent, sizeof(continent), city, sizeof(city));
    printf("4\n\tCountry: %s\n\tContinent: %s\n\tCity: %s\n", country, continent, city);

    ndpi_exit_detection_module(ndpi_info_mod);

    return 0;
}
