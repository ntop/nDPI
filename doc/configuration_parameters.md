
# Configuration knobs

TODO

| Protocol     | Parameter                                 | Default value | Min value | Max value | Description | Notes  |
| ------       | ------                                    | ------        | ------    | ------    | ------      | ------ |
| NULL         | "packets_limit_per_flow"                  | 32            | 0         | 255       | The upper limit on the number of packets per flow that will be subject to DPI, after which classification will be considered complete (0 = no limit) |
| NULL         | "filename.config"                         | NULL          | NULL      | NULL      | Name of the file containing a list of configuration knobs itself (one per line)!. Useful to configure nDPI via text file instead of via API |
| "tls"        | "metadata.sha1_fingerprint.enable"        | 1             | NULL      | NULL      | Enable/disable computation and export of SHA1 fingerprint for TLS flows. Note that if it is disable, the flow risk `NDPI_MALICIOUS_SHA1_CERTIFICATE` is not checked |
