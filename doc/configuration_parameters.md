
# Configuration knobs

TODO

| Protocol     | Parameter                                 | Default value | Min value | Max value | Description | Notes  |
| ------       | ------                                    | ------        | ------    | ------    | ------      | ------ |
| NULL         | "packets_limit_per_flow"                  | 32            | 0         | 255       | The upper limit on the number of packets per flow that will be subject to DPI, after which classification will be considered complete (0 = no limit) |
| NULL         | "filename.config"                         | NULL          | NULL      | NULL      | Name of the file containing a list of configuration knobs itself (one per line)!. Useful to configure nDPI via text file instead of via API |
| "tls"        | "metadata.sha1_fingerprint.enable"        | 1             | NULL      | NULL      | Enable/disable computation and export of SHA1 fingerprint for TLS flows. Note that if it is disable, the flow risk `NDPI_MALICIOUS_SHA1_CERTIFICATE` is not checked |
| NULL         | "lru.$CACHE_NAME.size"                    | See description | 0         | 16777215  | Set the size (in number of elements) of the specified LRU cache (0 = the cache is disabled). The keyword "$CACHE_NAME" is a placeholder for the cache name and the possible values are: ookla, bittorrent, zoom, stun, tls_cert, mining, msteams, stun_zoom. The default value is "32768" for the bittorrent cache, "512" for the zoom cache and "1024" for all the other caches |
| NULL         | "lru.$CACHE_NAME.ttl"                     | See description | 0         | 16777215  | Set the TTL (in seconds) for the elements of the specified LRU cache (0 = the elements never explicitly expire). The keyword "$CACHE_NAME" is a placeholder for the cache name and the possible values are: ookla, bittorrent, zoom, stun, tls_cert, mining, msteams, stun_zoom. The default value is "120" for the ookla cache, "60" for the msteams and stun_zoom caches and "0" for all the other caches |
