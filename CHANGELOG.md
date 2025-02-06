# CHANGELOG

#### nDPI 4.12 (Dec 2024)

## Major Changes

- Added detection of encrypted/obfuscated OpenVPN flows (https://github.com/ntop/nDPI/pull/2547, https://github.com/ntop/nDPI/pull/2560)
- Added detection of encrypted/obfuscated/proxied TLS flows (https://github.com/ntop/nDPI/pull/2553)
- Implemented nDPI TCP fingerprint (https://github.com/ntop/nDPI/commit/6b6dad4fdb2e60cd2887f7d381bcab2387ba9507)

For further details on these three topics, see https://www.ntop.org/ntop/a-deep-dive-into-traffic-fingerprints/

## New Supported Protocols and Services

This is the list of the new supported protocols, grouped by category.
Information about these new protocols is available on https://github.com/ntop/nDPI/blob/dev/doc/protocols.rst

* `NDPI_PROTOCOL_CATEGORY_IOT_SCADA`:
  * `NDPI_PROTOCOL_CNP_IP` (https://github.com/ntop/nDPI/pull/2521, https://github.com/ntop/nDPI/pull/2531)
  * `NDPI_PROTOCOL_ATG`  (https://github.com/ntop/nDPI/pull/2527)
  * `NDPI_PROTOCOL_TRDP` (https://github.com/ntop/nDPI/pull/2528)
  * `NDPI_PROTOCOL_DICOM` (https://github.com/ntop/nDPI/commit/4fd12278b111eeaf1068876f77fb0a6176f69a34)
* `NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER`:
  * `NDPI_PROTOCOL_LUSTRE` (https://github.com/ntop/nDPI/pull/2544)
* `NDPI_PROTOCOL_CATEGORY_VPN`:
  * `NDPI_PROTOCOL_NORDVPN` (https://github.com/ntop/nDPI/commit/f350379e95935448c22a387a561b57d50251f422)
  * `NDPI_PROTOCOL_SURFSHARK` (https://github.com/ntop/nDPI/commit/5b0374c28b60a39f5720cb44ea5f711774c511af)
  * `NDPI_PROTOCOL_CACTUSVPN` (https://github.com/ntop/nDPI/commit/c99646e4afee9489de9b62d7cb9b81176f6c01a3)
  * `NDPI_PROTOCOL_WINDSCRIBE` (https://github.com/ntop/nDPI/commit/2964c23ca1f9af4df5c93e337987c6823b2ac663)
* ` NDPI_PROTOCOL_CATEGORY_MUSIC`:
  * `NDPI_PROTOCOL_SONOS` (https://github.com/ntop/nDPI/commit/806f47337d591b82ba2db211629b2b25429cc21e)
* `NDPI_PROTOCOL_CATEGORY_CHAT`:
  * `NDPI_PROTOCOL_DINGTALK` (https://github.com/ntop/nDPI/pull/2581)
  * `NDPI_PROTOCOL_PALTALK` (https://github.com/ntop/nDPI/pull/2606)
* `NDPI_PROTOCOL_CATEGORY_WEB`:
  * `NDPI_PROTOCOL_NAVER` (https://github.com/ntop/nDPI/pull/2610)
* `NDPI_PROTOCOL_CATEGORY_SHOPPING`:
  * `NDPI_PROTOCOL_SHEIN` (https://github.com/ntop/nDPI/pull/2615)
  * `NDPI_PROTOCOL_TEMU` (https://github.com/ntop/nDPI/pull/2615)
  * `NDPI_PROTOCOL_TAOBAO`  (https://github.com/ntop/nDPI/pull/2615)
* `NDPI_PROTOCOL_CATEGORY_NETWORK`:
  * `NDPI_PROTOCOL_MIKROTIK` (https://github.com/ntop/nDPI/pull/2618)
* `NDPI_PROTOCOL_CATEGORY_STREAMING`:
  * `NDPI_PROTOCOL_PARAMOUNTPLUS` (https://github.com/ntop/nDPI/pull/2628)
* `NDPI_PROTOCOL_CATEGORY_VIRTUAL_ASSISTANT`:
  * `NDPI_PROTOCOL_YANDEX_ALICE` (https://github.com/ntop/nDPI/pull/2633)

## New features

* Implemented JA4 raw fingerprint (https://github.com/ntop/nDPI/commit/42ded07139e41c54a9ae2c8875a9e2c56d50af41)
* Add monitoring capability (for STUN flows) (https://github.com/ntop/nDPI/pull/2588). See also: https://github.com/ntop/nDPI/blob/dev/doc/monitoring.md
* Implemented DNS host cache (https://github.com/ntop/nDPI/commit/55fa92490af593358a0b13ad1708ee9b14eec128)
* Add a configuration file to `ndpiReader` (https://github.com/ntop/nDPI/pull/2629)

## New algorithms

* Implemented algorithms for K-Nearest Neighbor Search (KNN)  (https://github.com/ntop/nDPI/pull/2554)
* Added `ndpi_quick_encrypt()` and  `ndpi_quick_decrypt()` API calls (https://github.com/ntop/nDPI/pull/2568)

## New configuration knobs

Further information is available on https://github.com/ntop/nDPI/blob/dev/doc/configuration_parameters.md

* `tls,subclassification`, `quic,subclassification`, `http,subclassification`: enable/disable subclassification (https://github.com/ntop/nDPI/pull/2533)
* `openvpn,subclassification_by_ip`, `wiregurad,subclassification_by_ip`: enable/disable sub-classification using server IP. Useful to detect the specific VPN application/app (https://github.com/ntop/nDPI/commit/85ebda434d44f93e656ee5d3e52dc258134495d0)
* `openvpn,dpi.heuristics`, `openvpn,dpi.heuristics.num_messages`: configure heuristics to detect OpenVPN flows (https://github.com/ntop/nDPI/pull/2547)
* `dpi.guess_ip_before_port`: enable/disable guessing by IP first when guessing flow classifcation (https://github.com/ntop/nDPI/pull/2562)
* `tls,dpi.heuristics`, `tls,dpi.heuristics.max_packets_extra_dissection`: configure heuristics to detect TLS flows (https://github.com/ntop/nDPI/pull/2553)
* `flow.use_client_ip_in_guess`, `flow.use_client_port_in_guess`: configure guessing algorithm (https://github.com/ntop/nDPI/pull/2569)
* `$PROTO_NAME,monitoring`: enable/disable monitoring state (https://github.com/ntop/nDPI/pull/2588)
* `metadata.tcp_fingerprint`, `tls,metadata.ja4r_fingerprint`: enable/disable some fingerprints (https://github.com/ntop/nDPI/commit/6b6dad4fdb2e60cd2887f7d381bcab2387ba9507, https://github.com/ntop/nDPI/commit/42ded07139e41c54a9ae2c8875a9e2c56d50af41)
* `sip,metadata.attribute.XXX`: enable/disable extraction of some SIP metadata (https://github.com/ntop/nDPI/pull/2614)

## Improvements

* Fixed probing attempt risk that was creating false positives (https://github.com/ntop/nDPI/commit/fc4fb4d409c43af8b9bdbd9d0cf8d9b742408f26)
* Fixes Viber false positive detection (https://github.com/ntop/nDPI/commit/5610145c6c2f0aebd6adee7717145ab44c29f848)
* ahocorasick: fix mem leaked AC_NODE_T object (https://github.com/ntop/nDPI/pull/2258, https://github.com/ntop/nDPI/pull/2522)
* Endian-independent implementation of IEEE 802.3 CRC32 (https://github.com/ntop/nDPI/pull/2529)
* Improved Yahoo matching for Japanese traffic (https://github.com/ntop/nDPI/pull/2539)
* HTTP, QUIC, TLS: allow to disable sub-classification (https://github.com/ntop/nDPI/pull/2533)
* Bittorrent fixes (https://github.com/ntop/nDPI/pull/2538)
* bins: fix `ndpi_set_bin`, `ndpi_inc_bin` and `ndpi_get_bin_value` (https://github.com/ntop/nDPI/pull/2536)
* TLS: better state about handshake (https://github.com/ntop/nDPI/pull/2534)
* OpenVPN: improve detection (https://github.com/ntop/nDPI/commit/c713c894b6146c7884e24895cd3df1d7e35ee120)
* OpenVPN, Wireguard: improve sub-classification (https://github.com/ntop/nDPI/commit/85ebda434d44f93e656ee5d3e52dc258134495d0)
* oracle: fix dissector (https://github.com/ntop/nDPI/pull/2548)
* RTMP: improve detection (https://github.com/ntop/nDPI/pull/2549)
* RTP: fix identification over TCP (https://github.com/ntop/nDPI/commit/def86ba0a9f090cebda3d2e521e22f5d8f2f0f35)
* QUIC: add a basic heuristic to detect mid-flows (https://github.com/ntop/nDPI/pull/2550)
* Enhanced DHCP fingerprint (https://github.com/ntop/nDPI/commit/b77d3e3ab6d216cda9a092794a5fb8b1eac86fe6)
* dns: add a check before setting `NDPI_MALFORMED_PACKET` risk (https://github.com/ntop/nDPI/pull/2558)
* Tls out of order (https://github.com/ntop/nDPI/pull/2561)
* Added DHCP class identifier (https://github.com/ntop/nDPI/commit/7cc2432098ccd85c6de34e177f1115272c8d382b)
* Improved fingerprint serialization (https://github.com/ntop/nDPI/commit/40fefd59a7bcf087c89c1f62adfc2fb8eccb126a)
* Fixed handling of spurious TCP retransmissions (https://github.com/ntop/nDPI/commit/eeb1c281adae5002d8f9c981c0b145a88a814548)
* TLS: improve handling of Change Cipher message (https://github.com/ntop/nDPI/pull/2564)
* Added pki.goog domain name (https://github.com/ntop/nDPI/commit/26b1899d9274b07b04032468e33a14a36756a63f)
* TTL Cache Fix (https://github.com/ntop/nDPI/pull/2582)
* Added STUN fingerprint code (https://github.com/ntop/nDPI/commit/ab3e07335409f5c0710cdffbbf7091578f18f128)
* TLS: heuristics: fix memory allocations (https://github.com/ntop/nDPI/pull/2577)
* TLS: detect abnormal padding usage (https://github.com/ntop/nDPI/pull/2579)
* Enhanced DHCP fingerprint (https://github.com/ntop/nDPI/commit/4df60a888b374e4b41298d0d63f98fcaff05786d)
* STUN: fix monitoring of Whatsapp and Zoom flows (https://github.com/ntop/nDPI/pull/2590
* Exports DNS A/AAAA responses (up to 4 addresses) (https://github.com/ntop/nDPI/commit/45323e3bf8a0fc56fd5f74c12f78e2f27429e701)
* Added new API calls for serializing/restoring the DNS cache (https://github.com/ntop/nDPI/commit/b9348e9d6e0e754c4b17661c643ca258f1540ca1)
* Fixed JA4 invalid computation due to code bug and uninitialized values (https://github.com/ntop/nDPI/commit/2b4061108215304c131aea314229719975c8f1d9)
* Add configuration of TCP fingerprint computation (https://github.com/ntop/nDPI/pull/2598)
* STUN: if the same metadata is found multiple times, keep the first value (https://github.com/ntop/nDPI/pull/2591)
* STUN: minor fix for RTCP traffic (https://github.com/ntop/nDPI/pull/2593)
* Added support for RDP over TLS (https://github.com/ntop/nDPI/commit/6dc4533c3cc0786c740f91cedab74e54623349b2)
* STUN: fix monitoring with RTCP flows (https://github.com/ntop/nDPI/pull/2603)
* Fixes TCP fingerprint calculation when multiple EOL are specified (https://github.com/ntop/nDPI/commit/d5236c0aafe0b9622da752147ff4fbafd52e7582)
* Added DHCP fingerprint (https://github.com/ntop/nDPI/commit/fecc378e0426cbad42da636bb075dadb3fb24e61)
* DNS reponse addresses are now serialized in JSON (https://github.com/ntop/nDPI/commit/0d4c1e9179d03ee099a943f8420c54174c976da7)
* TikTok cleanup (https://github.com/ntop/nDPI/commit/a97a130e59d635c5acfccf6049499d201dc90ba3)
* Added HTTP credentials extraction (https://github.com/ntop/nDPI/commit/412ca8700fc53da705c6aa386c736a400279a614)
* TLS: export heuristic fingerprint as metadata (https://github.com/ntop/nDPI/pull/2609)
* SIP: rework detection and extract metadata (https://github.com/ntop/nDPI/pull/2614)
* Zoom: fix heap-buffer-overflow (https://github.com/ntop/nDPI/pull/2621)
* Small updates on domains list (https://github.com/ntop/nDPI/pull/2623)
* RTP, STUN: improve detection of multimedia flow type (https://github.com/ntop/nDPI/pull/2620)
* Update `flow->flow_multimedia_types` to a bitmask (https://github.com/ntop/nDPI/pull/2625)
* Improved TCP probing attempt (https://github.com/ntop/nDPI/commit/9e67885aff6bbfc41157c620752a6770b6b62b23)
* When triggering risk "Known Proto on Non Std Port", nDPi now reports the port that was supposed to be used as default (https://github.com/ntop/nDPI/commit/56e52448c43ee069b283501327bd15067d877d57)
* SIP: export metadata via json (https://github.com/ntop/nDPI/pull/2630)
* STUN: improve Whatsapp monitoring (https://github.com/ntop/nDPI/pull/2635)
* Enhanced STUN stats](https://github.com/ntop/nDPI/commit/6b6b5c7c4e4e6112dcd6722a8685ee3517d7d5bc)
* Added STUN custom support (https://github.com/ntop/nDPI/commit/ea1b8dc1cb3caffbe4937c9b8ca1a3ecde4c3351)
* signal: improve detection of chats and calls (https://github.com/ntop/nDPI/pull/2637)
* STUN: fix monitoring (https://github.com/ntop/nDPI/pull/2639)
* STUN/RTP: improve metadata extraction (https://github.com/ntop/nDPI/pull/2641)
* Added minor Citrix improvement (https://github.com/ntop/nDPI/commit/727d08deef1de94409db1b9aa45a49cf016a547a)
* Telegram STUN improvement (https://github.com/ntop/nDPI/commit/4d17dc635cac296ae2f526c1d56a90c6d60170d8)

## Misc

* Fix `verify_dist_tarball.sh` after latest release (https://github.com/ntop/nDPI/pull/2519)
* Removed unnecessary includes (https://github.com/ntop/nDPI/pull/2525)
* Fixed initialization (https://github.com/ntop/nDPI/commit/e72255445c5654d1d1f932583fbf5f01c187e946, https://github.com/ntop/nDPI/commit/9b1736aa8960170d32eac7c954194eff9436fbbc)
* Fix url for downloading X/Twitter crawler IPs (https://github.com/ntop/nDPI/pull/2526)
* Introduced `ndpi_master_app_protocol` typedef (https://github.com/ntop/nDPI/commit/53a6bae365618f9b301cf51e5f3f9d5450b0e280)
* Added `ndpi_get_protocol_by_name*` API call (https://github.com/ntop/nDPI/commit/f7ee92c690ebce8841f1ab973b3d63146952f912)
* Changed `NDPI_MALICIOUS_JA3` to `NDPI_MALICIOUS_FINGERPRINT` (https://github.com/ntop/nDPI/commit/bad0e60813e0b23a0cd96c92e58b9caa08eb8dec)
* Added `ndpi_is_proto_*` and `ndpi_get_proto_by_*` API call (https://github.com/ntop/nDPI/commit/9263d4dd873c4e2068e392a692b20609b1ec5a9a)
* Added `ndpi_risk2code` and `ndpi_code2risk` API call (https://github.com/ntop/nDPI/commit/5436dddef55e068095ca56b114715a91a551bf26)
* Added `print_ndpi_address_port` in nDPi API (https://github.com/ntop/nDPI/commit/d769b23e05f93158302cf6904b182860b05545e9)
* Print risk code in `ndpi_dump_risks_score` (https://github.com/ntop/nDPI/commit/69fd4aadf3ed362ba67f03975f8b72c733bca7f7)
* Align serialized risk names to all others (first letter; uppercase letter) (https://github.com/ntop/nDPI/pull/2541)
* wireshark: extcap: fix output data link type (https://github.com/ntop/nDPI/pull/2543)
* wireshark: extcap: export flow risk info (https://github.com/ntop/nDPI/commit/23ae3d0c265590a138f156c2193998e3b8f2fdd5)
* Added -E option for dumping flow fingerprint (https://github.com/ntop/nDPI/commit/fda3730cf0bdec6b4a1cd8e38d3a88c33f0d0ef1)
* Reworked fingerprint export now in JSON (https://github.com/ntop/nDPI/commit/6de91c78955a0d85d97518c273366bd9d6ede5de)
* wireshark: extcap: rework trailer header (https://github.com/ntop/nDPI/pull/2557)
* fuzz: try to be a little bit faster (https://github.com/ntop/nDPI/pull/2559, https://github.com/ntop/nDPI/pull/2570, https://github.com/ntop/nDPI/pull/2578)
* domain lists are not loaded when -E is used (https://github.com/ntop/nDPI/commit/1d1edfc1c787bfe91d457f632c148447f8912842)
* Implemented ndpi_strrstr() (https://github.com/ntop/nDPI/commit/191694f797639fc0b56adcf050bc9cfa8dc02f3d, https://github.com/ntop/nDPI/pull/2570)
* Allow IP guess before port in `ndpi_detection_giveup` (https://github.com/ntop/nDPI/pull/2562)
* Replaced traces with debug messages (https://github.com/ntop/nDPI/commit/08a37dc779dde9f85989459a946195e1d22914fc)
* wireshark: lua: add script for QUIC fingerprints (https://github.com/ntop/nDPI/pull/2566)
* Added new API calls `ndpi_hex2bin` and `ndpi_bin2hex` (https://github.com/ntop/nDPI/commit/42cfd29cc3d7dd2c883c8fd3c5f53319f752fbfc) 
* Add enable/disable guessing using client IP/port (https://github.com/ntop/nDPI/pull/2569)
* CI: add tests on macos-15 (https://github.com/ntop/nDPI/pull/2571)
* Let the library returning the packet direction calculated internally (https://github.com/ntop/nDPI/pull/2572)
* wireshark: extcap: allow configuration of OpenVPN/TLS heuristics via GUI (https://github.com/ntop/nDPI/pull/2576)
* CI: remove macos-12 (https://github.com/ntop/nDPI/pull/2592)
* Moved ndpi_lru in a separate file (https://github.com/ntop/nDPI/commit/7629b94a2671611b302a7d95a5392f78c6729f77)
* Added -N option for dumping/restoring the DNS cache (when enabled) (https://github.com/ntop/nDPI/commit/2e5edd2cc956b420f6b9e2a2ffec7d435694a69a)
* Added JA4 stats (https://github.com/ntop/nDPI/commit/b53e4fc661377fe7f9cc135d46db2d5dd15060ab)
* Added support for printing JA4r when enabled (https://github.com/ntop/nDPI/commit/faaa5c5799440117f7a9cc78499433396dba7eb3)
* Added TLS fingerprints (https://github.com/ntop/nDPI/commit/37a654e33fc03c2cd0c956e860b634b2ad7d5b60)
* Added `ndpi_is_public_ipv4` (https://github.com/ntop/nDPI/commit/3e04321eab515992ef2af96af916fa5155f07a7e)
* Parser for ndpiReader JSON files (https://github.com/ntop/nDPI/commit/97ce7293920646d3b8e052ef467d23f086baf982)
* Added -L <domain suffix> for loading domain suffixes (https://github.com/ntop/nDPI/commit/afc4d9e34d61a45c5daeffcdcc187bc0b105ef3e)
* ndpiReader: add some statistics about monitoring (https://github.com/ntop/nDPI/pull/2602)
* ndpiReader: explicitly remove non ipv4/6 packets (https://github.com/ntop/nDPI/pull/2601)
* Fix `ndpi_tot_allocated_memory` calculation if `ndpi_calloc()` used (https://github.com/ntop/nDPI/pull/2604)
* ndpiReader: fix command line options used by wireshark (https://github.com/ntop/nDPI/pull/2605)
* ml tests for dga detection (https://github.com/ntop/nDPI/pull/2607)
* Add new json serialization type `ndpi_serialization_format_inner_json` (https://github.com/ntop/nDPI/commit/8ad34b381ca5d352dc4f877f93bc0f7625d8b28c)
* fuzz: improve coverage (https://github.com/ntop/nDPI/pull/2612)
* Exported `is_ndpi_proto` definition (https://github.com/ntop/nDPI/commit/183175fc6b4c9e610fb22dfd69946cc7063b6a63)
* Crash fix when -f is specified with a non-existing pcap file (-i) (https://github.com/ntop/nDPI/commit/35ef56cc2467e907fa1827a4e8058893dea0b8a7)
* Unify ndpi debug logging to always use a u16 protocol id (https://github.com/ntop/nDPI/pull/2613)
* Added ndpi_intoav6() (https://github.com/ntop/nDPI/commit/de8c326cd218867b88c25b0e6c0be9e2c909b1e9)
* Debian/Ubuntu packaging: use `--enable-no-sign` to build `*.deb` packages w/o signing those (https://github.com/ntop/nDPI/pull/2616)
* ndpiReader: fix statistic about total number of flows (https://github.com/ntop/nDPI/pull/2622)
* Update GitHub CI actions (https://github.com/ntop/nDPI/pull/2627)
* Removed old USE_LEGACY_AHO_CORASICK code (https://github.com/ntop/nDPI/commit/170849f156fe7b803eb08f91722bfaa576f3084f)
* Fix license typo (https://github.com/ntop/nDPI/pull/2638)
* Update script to download Azure IP list ranges (https://github.com/ntop/nDPI/pull/2640)
* Update all IPS lists (https://github.com/ntop/nDPI/pull/2643)

## New Contributors

* @wssxsxxsx made their first contribution in https://github.com/ntop/nDPI/pull/2527
* @liwilson1 made their first contribution in https://github.com/ntop/nDPI/pull/2539
* @YellowMan02 made their first contribution in https://github.com/ntop/nDPI/pull/2607
* @Klavishnik made their first contribution in https://github.com/ntop/nDPI/pull/2633
* @adipierro made their first contribution in https://github.com/ntop/nDPI/pull/2638

**Full Changelog**: https://github.com/ntop/nDPI/compare/4.10...4.12



#### nDPI 4.10 (Aug 2024)

## Major Changes
- Initial work towards First Packet Classification (FPC)

## New Supported Protocols and Services
- Add OpenWire support (#2513)
- FPC: add DNS correlation  (#2497)
- ipaddr2list.py, ndpi2timeline.py: reformatted (#2509)
- Add Nano (XNO) protocol support (#2508)
- Added ClickHouse protocol
- Add HLS support (#2502)
- Add infrastructure for explicit support of Fist Packet Classification (#2488)
- Add detection of Twitter bot (#2487)
- Added default port mappings to ndpiReader help -H (#2477)
- Add Ripe Atlas probe protocol. (#2473)
- Add ZUG consensus protocol dissector. (#2458)
- Added NDPI_PROBING_ATTEMPT risk
- DTLS: add support for DTLS 1.3 (#2445)
- Added dpi.compute_entropy configuration parameter
- Add Call of Duty Mobile support (#2438)
- Add Ethernet Global Data support (#2437)
- Viber: add detection of voip calls and avoid false positives (#2434)
- Add support for Mastodon, Bluesky and (FB-)Threads (#2418)
- Fixes JA4 computation adding a better GREASE detect funzion
- DTLS: add support for Alert message type (similar to TLS) (#2406)
- Add Adobe Connect support (#2407)
- Remove PPStream protocol and add iQIYI (#2403)
- Add BFCP protocol support (#2401)
- Add strlcpy implementation (#2395)
- Add KNXnet/IP protocol support (#2397)
- STUN: add support for ipv6 in some metadata (#2389)
- Implemented STUN peer_address, relayed_address, response_origin, other_address parsing Added code to ignore invalid STUN realm Extended JSON output with STUN information
- Add Label Distribution Protocol support (#2385)
- Add The Elder Scrolls Online support (#2376)
- Add Shellscript risk detection. (#2375)
- Add PE32/PE32+ risk detection (detect transmitted windows executables). (#2312)
- Added support for STUN Mapped IP address
- Added binary data transfer risk alert
- Add LoL: Wild Rift detection (#2356)
- STUN: add dissection of XOR-PEER-ADDRESS with ipv6 address
- Add FLUTE protocol dissector (#2351)
- Add PFCP protocol dissector (#2342)
- Add Path of Exile protocol dissector (#2337)
- Add NetEase Games detection support (#2335)
- Add Naraka Bladepoint detection support (#2334)
- Add BFD protocol dissector (#2332)
- Add DLEP protocol dissector (#2326)
- Add ANSI C12.22 protocol dissector (#2317)
- TLS: add configuration of JA* fingerprints (#2313)
- Add detection of Gaijin Entertainment games (#2311)
- Add new AppsFlyer domain (#2307)
- Add TencentGames protocol dissector (#2306)
- Add Gearman protocol dissector (#2297)
- Add Raft protocol dissector. (#2286)
- Add Radmin protocol dissector (#2283)
- Add STOMP protocol dissector (#2280)
- Add ElectronicArts detection support (#2274)
- Add Yojimbo (netcode) protocol dissector (#2277)
- Add a dedicated dissector for Zoom (#2265)
- Add Mumble detection support (#2269)
- Add KCP protocol dissector. (#2257)
- Add PIA (Private Internet Access) support (#2250)
- Add more adult content hostnames (#2247)
- Add Roughtime protocol dissector. (#2248)
- Add realtime protocol output to `ndpiReader`. (#2197)
- Add Google Chat support (#2244)
- ndpiReader: add breed stats on output used for CI (#2236)
- Add Ceph protocol dissector (#2242)
- Add HL7 protocol dissector (#2240)
- Add IEC62056 (DLMS/COSEM) protocol dissector (#2229)
- Add NoMachine NX protocol dissector (#2234)
- Add Apache Kafka protocol dissector (#2226)
- Add WebDAV detection support (#2224)
- Add JSON-RPC protocol dissector (#2217)
- Add OpenFlow protocol dissector (#2222)
- Add UFTP protocol dissector (#2215)
- Add HiSLIP protocol dissector (#2214)
- Add PROFINET/IO protocol dissector (#2213)
- Add Monero protocol classification. (#2196)
- Add Ether-S-Bus protocol dissector (#2200)
- Add IEEE C37.118 protocol dissector (#2193)
- Add ISO 9506-1 MMS protocol dissector (#2189)
- Add Beckhoff ADS protocol dissector (#2181)
- Add Schneider Electric’s UMAS detection support (#2180)
- Add Ether-S-I/O protocol dissector (#2174)
- Add Omron FINS protocol dissector (#2172)
- Rework S7Comm dissector; add S7Comm Plus support (#2165)
- Add OPC UA protocol dissector (#2169)
- Add RTPS protocol dissector (#2168)
- Add HART-IP protocol dissector (#2163)
- Add IEEE 1588-2008 (PTPv2) dissector (#2156)
- Added TeslaServices and improved TikTok host names. Fixes #2140. (#2144)
- Add ethereum protocol dissector. (#2111)
- Added generic Google Protobuf dissector. (#2109)
- Add CAN over Ethernet dissector.
	
	
## Improvements

 - Enhanced PrimeVideo detection
 - Enhanced ookla tracing
 - Improved ICMP malformed packet risk description
- Improve detection of Cloudflare WARP traffic (#2491)
- tunnelbear: improve detection over wireguard (#2485)
- Improve detection of Twitter/X (#2482)
- Zoom: fix detection of screen sharing (#2476)
 - Improved detection of Android connectiity checks
 - Zoom: fix integer overflow (#2469)
 - RTP/STUN: look for STUN packets after RTP/RTCP classification (#2465)
 - Zoom: faster detection of P2P flows (#2467)
 - Added NDPI_PROTOCOL_NTOP assert and removed percentage comparison (#2460)
- Add extra entropy checks and more precise(?) analysis. (#2383)
- STUN: improve extraction of Mapped-Address metadata (#2370)
- Added support for roaring bitmap v3 (#2355)
- Add more TencentGames signatures (#2354)
- Added DGA exception for Dropbox
- QUIC: add heuristic to detect unidirectional *G*QUIC flows (#2207)
- fuzzing: improve coverage (#2495)
- Improve detection of Cloudflare WARP traffic (#2491)
- fuzz: improve fuzzers using pl7m (#2486)
- wireshark: lua: minor improvements
- Improved logic for checking invalid DNS queries
- fuzz: improve fuzzing coverage (#2474)
- Improved Kafka dissector. (#2456)
- H323: improve detection and avoid false positives (#2432)
- Fix/improve fuzzing (#2426) (#2400)
- eDonkey: improve/update classification (#2410)
- Domain Classification Improvements  (#2396)
- STUN: improve extraction of Mapped-Address metadata (#2370)
- Improve LoL: Wild Rift detection (#2359)
- Improve TencentGames detection (#2353)
- STUN: improve heurstic to detect old classic-stun
- ahocorasick: improve matching with subdomains (#2331)
- Improved alert on suspicious DNS traffic
- Telegram: improve identification
- Improved Telegram detection
- Improved modbus dissection to discard false positives
- Improved Polish gambling sites fetch script. (#2315)
- fuzz: improve fuzzing coverage (#2309)
- Improve normalization of `flow->host_server_name` (#2310)
- Improve `ndpi_set_config` error printing. (#2300)
- Improve MySQL detection (#2279)
- Improve handling of custom rules (#2276)
- Zoom: improve detection (#2270)
- Improved ndpi_get_host_domain
- Bittorrent: improve detection of UTPv1 (#2259)
- Improved uTorrent via utp (TCP-like streams over UDP). (#2255)
- fuzz: improve fuzzing coverage (#2239)
- fuzz: improve fuzzing coverage (#2220)
- Improved belgium gambling sites regex. (#2184)
- Improve CORBA detection (#2167)
- STUN: improve demultiplexing of DTLS packets (#2153)
- Improved TFTP. Fixes #2075. (#2149)
- fuzz: improve coverage and remove dead code (#2135)
- Improved Protobuf dissector. (#2119)
- Improved detection as non DGA for hostnames belnging to a CDN (#2068)
- Improved CryNetwork protocol dissector.

## Tools
- Make the CI faster (#2475)
- Add a script to download/update the domain suffix list (#2321)
- Add identification of Huawei generic and cloud traffic (#2325)
- ndpiReader: improve the check on max number of pkts processed per flow (#2261)
- Added default port mappings to ndpiReader help -H (#2477)
- ndpiReader: restore `ndpiReader -x $DOMAIN_NAME` functionality (#2329)
- ndpiReader: improve the check on max number of pkts processed per flow (#2261)
- ndpiReader: fix memory leak
- Add realtime protocol output to `ndpiReader`. (#2197)
- ndpiReader: add breed stats on output used for CI (#2236)
- ndpiReader: avoid creating two detection modules when processing traffic/traces (#2209)
- ndpiReader: fix `guessed_flow_protocols` statistic (#2203)

## Misc
- Improved tests coverage
- Varisous performance improvements
- Added stress test
- Added new API calls - ndpi_load_domain_suffixes() - ndpi_get_host_domain_suffix()
- Add some fast CRC16 algorithms implementation (#2195)
- Add a FAQ for the project (#2185)
- Ip address list: aggregate Mullvad and Tor lists too (#2154)
- IP lists: aggregate addresses wherever possible (#2152)
- Added malicious sites from the polish cert. (#2121)
- IPv6: add support for custom categories (#2126)
- IPv6: add support for IPv6 risk exceptions (#2122)
- IPv6: add support for custom rules (#2120)
- IPv6: add support for IPv6 risk tree (#2118)
- ipv6: add support for ipv6 addresses lists (#2113)



#### nDPI 4.8 (Oct 2023)

## Major Changes
- Reworked lists implementation that decreased memory usage of orders of magnitude
- Improved code robustness via extensive code fuzzing
- Various improvements to overall library performance
- Extended IPv6 support

## New Supported Protocols and Services
	
 - Add "Heroes of the Storm" video game signature detection. (#1949)
 - Add Apache Thrift protocol dissector. (#2007)
 - Add Remote Management Control Protocol (RMCP).
 - Add Service Location Protocol dissector. (#2036)
 - Add VK detection (#1880)
 - Add Yandex services detection (#1882)
 - Add a new protocol id for generic Adult Content traffic (#1906)
 - Add a new protocol id for generic advertisement/analytics/tracking stuff (#1904)
 - Add bitcoing protocol dissector. (#1992)
 - Add detection of Roblox games (#2054)
 - Add support for (un-encrypted) HTTP/2 (#2087)
 - Add support for Epic Games and GeForceNow/Nvidia (#1990)
 - Add support for SRTP (#1977)
 - Added BACnet dissector. (#1940)
 - Added HAProxy protocol. (#2088)
 - Added OICQ dissector. (#1950)
 - Added OperaVPN detection
- ProtonVPN: add basic detection (#2006)
 - Added detection of Facebook Reels and Stories
 - Add an heuristic to detect fully encrypted flows (#2058)
 - Added NDPI_MALWARE_HOST_CONTACTED flow risk
 - Added NDPI_TLS_ALPN_SNI_MISMATCH flow risk

## Improvements

 - Improve protocol detection for:
 - FreeBSD compilation fix (C) update
 - Gnutella: improve detection (#2019)
 - H323: fix false positives (#1916)
 - HTTP: fix another memory access error (#2049)
 - HTTP: fix extraction of filename (#2046)
 - HTTP: fix heap-buffer-overflow (#2044)
 - HTTP: improve extraction of metadata and of flow risks (#1959)
 - HTTP: remove useless code about XBOX (#1958)
 - HTTP: rework state machine (#1966)
 - Hangout: detect Hangout/Duo/GoogleMeet/... in the STUN code (#2025)
 - Enhance DNS risk for long hostnames (> 32)
 - Enhanced MS teams STUN/Azure detection
 - Enhanced custom port definition and improved error reporting in case of duplications
 - Improve detection of Alibaba flows (#1991)
 - Improve detection of crawler/bot traffic (#1956)
 - Improve detection of crawlers/bots (#1968)
 - Improved MGCP detection by allowing '\r' as line feed.
 - Improved MS Teams detection with heuristic
 - Improved Steam detection by adding steamdiscover pattern. (#2105)
 - Improved Wireguard detection
 - Improved checks for duplicated entries in protocols file
 - Improved classification further reducing memory used
 - Improved detection of invalid chars in DNS names
 - Improved domain search tet unit
 - Improved helper scripts. (#1986)
 - MS Teams enhancement
 - MySql: improve detection (#1928)
 - zabbix: improve detection (#2055)
	
## Tools

 - ndpiReader: allow to configure LRU caches TTL and size (#2004)
 - ndpiReader: fix VXLAN de-tunneling (#1913)
 - ndpiReader: fix export of DNS/BitTorrent attributes (#1985)
 - ndpiReader: fix export of HTTP attributes (#1982)
 - ndpiReader: fix flow stats (#1943)
 - ndpiReader: fix print of flow payload (#1960)
 - ndpiReader: improve printing of payload statistics (#1989)
 - ndpiReader: print how many packets (per flow) were needed to perform full DPI (#1891)
 - ndpireader: fix detection of DoH traffic based on packet distributions (#2045)

## Misc
 - ARM compilation fix
 - Add `ndpi_domain_classify_finalize()` function (#2084)
 - Add a configuration knob to enable/disable loading of gambling list (#2047)
 - Add a new flow risk about literal IP addresses used as SNI (#1892)
 - Add an heuristic to detect/ignore some anomalous TCP ACK packets (#1948)
 - Add another example of custom rules (#1923)
 - Add support for multiline json
 - Add support for roaring_bitmap_xor_inplace (#1983)
 - Add support for vxlan decapsulation (#1441) (#1900)
 - Added Source Engine dissector. (#1937)
 - Added `lists/gambling.list` to extra dist.
 - Added `slackb.com` SNI. (#2067)
 - Added ability to define an unlimited number of custom rules IP:port for the same IP (it used tobe limited to 2)
 - Added check to avoid skype heuristic false positives
 - Added comment
 - Added coverage targets to `Makefile.am` for convenience. (#2039)
 - Added fix for better handling exceptions rollback in case of later match
 - Added hyperlink
 - Added ndpi_binary_bitmap data structure
 - Added ndpi_bitmap64 support
 - Added ndpi_bitmap_andnot API call
 - Added ndpi_bitmap_copy() API call
 - Added ndpi_bitmap_is_empty() and ndpi_bitmap_optimize() API calls
 - Added ndpi_domain_classify_XXX(0 API
 - Added ndpi_filter_add_multi() API call
 - Added ndpi_murmur_hash to the nDPI API
 - Added new API calls for implementing Bloom-filter like data structures
 - Added printf/fprintf replacement for some internal modules. (#1974)
 - Added scripts to auto generate hostname/SNI *.inc files. (#1984)
 - Added sub-domain classification fix
 - Added the ability to define custom protocols with arbitrary Ids in proto.txt
 - Added vlan_id in ndpi_flow2json() prototype
 - Adds new pcap for testing "funny" HTTP servers
 - All protocols should be excluded sooner or later (#1969)
 - Allow init of app protocols w/o any hostnames set. (#2057)
 - Avoid calling `ndpi_reconcile_protocols()` twice in `ndpi_detection_giveup()` (#1996)
 - Boundary check
 - CI: fix `Performance` job (#1936)
 - Centos7 fixes
 - Changed logging callback function sig. (#2000)
 - Changes for supporting more efficient sub-string matching
 - Classification fixes
 - DNS: extract geolocation information, if available (#2065)
 - Debian 12 fixes
 - Disabled query string validation in MDNS in order to avoid zapping chars that in DNS (instead) are not permitted
 - DisneyPlus/Hulu ip lists should be auto-generated (#1905)
 - Extend content list of Microsoft protocols (#1930)
 - Extend content-match list (#1967)
 - Fix LRU/Patricia/Automa stats in `ndpiReader` with multiple threads (#1934)
 - Fix MS Teams detection with heuristic (#1972)
 - Fix access to packet/flow information (#2013)
 - Fix an heap-buffer-overflow (#1994)
 - Fix classification-by-ip in `ndpi_detection_giveup` (#1981)
 - Fix compilation (#2011)
 - Fix compilation in CI jobs (#2048)
 - Fix compilation on Windows (#2072)
 - Fix compilation with GCC-7 and latest RoaringBitmap code (#1886)
 - Fix detection of packet direction and NDPI_UNIDIRECTIONAL_TRAFFIC risk (#1883)
 - Fix export/serialization of `flow->risk` (#1885)
 - Fix for buffer overflow in serialization
 - Fix insert of ip addresses into patricia tree(s) (#1895)
 - Fix missing u_char, u_short and u_int typedefs for some platforms e.g.: (#2009)
 - Fix packet counters (#1884)
 - Fix some errors found by fuzzers (#2078)
 - Fix some memory errors triggered by allocation failures (#1995)
 - Fix some prototypes (#2085)
 - Fix string truncation. (#2056)
 - Fixed OpenWRT arm related build issues. (#2104)
 - Fixed heap-buffer-overflow issue
 - Fixed heap-overflow if compiled with `--enable-tls-sigs`. (#2038)
 - Fixed invalid use of ndpi_free(). Sorry, my fault. (#1988)
 - Fixed missing AS_HELP_STRING in configure.ac. (#1893)
 - Fixed two OpenWRT arm related build issues. (#2103)
 - Fixes matches with domain name strings that start with a dot
 - Fixes risk mask exception handling while improving the overall performance
 - Implemented Count-Min Sketch [count how many times a value has been observed]
 - Implemented Zoom/Teams stream type detection
 - Implemented ndpi_XXX_reset() API calls whre XXX is ses, des, hw
 - Implemented ndpi_predict_linear() for predicting a timeseries value overtime
 - Improved debug output. (#1951)
 - Improved invalid logging via printf().
 - Improved line protocol dissection with heuristic
 - Improved missing usage of nDPIs malloc wrapper. Fixes #1978. (#1979)
 - Improved protocol detection exploiting IP-based guess Reworked ndpi_reconcile_protocols() that is now called only in front of a match (less overhead)
 - Improvement for reducing false positives
 - Included Gambling website data from the Polish `hazard.mf.gov.pl` list (#2041)
 - Keep master protocol in `ndpi_reconcile_protocols`
 - Leak fix
 - Language fix
 - Line: fix heap-buffer-overflow error (#2015)
 - Made VK protocol detection more strict
 - Make Bittorrent LRU cache IPv6 aware. (#1909)
 - Merged new and old version of ndpi_domain_classify.c code
 - Mullvad VPN service added (based on entry node IP addresses) (#2062)
 - Numeric truncation at `ndpi_analyze.c` at lines 101, 104, 107, 110 (#1999)
 - Numeric truncation at `tls.c:1010` (#2005)
 - Ookla: rework detection (#1922)
 - Optimizes and fixes possible out0of0boundary write in ndpi_fill_prefix_v4()
 - ProtonVPN: split the ip list (#2060)
 - QUIC: add support for QUIC version 2
 - QUIC: export QUIC version as metadata
 - QUIC: fix a memory access error
 - QUIC: fix dissection of packets forcing VN
 - RDP: improve detection over UDP (#2043)
 - RTP: remove dead-code (#1953)
 - RTP: rework code (#2021)
 - Refreshed ASN lists Enhanced the Line IP list with https://ipinfo.io/AS23576/125.209.252.0/24 used by line
 - Remove some useless checks (#1993)
 - Remove special handling of some TCP flows without SYN (#1965)
 - Removed overlapping port
 - Renamed HTTP/2 to HTTP2 as the '/' can have side effects with applications sitting on top of nDPI
 - Replaces free() with ndpi_free()
 - Rework CI jobs to try reducing CI duration (#1903)
 - Reworked domain classification based on binary filters
 - Reworked initialization
 - Reworked ndpi_filter_xxx implementation using compressed bitmaps
 - Reworked teams handling
 - RiotGames: add detection of flows (#1935)
 - STUN: add dissection of DTLS handshake (#2018)
 - STUN: avoid FacebookVoip false positives (#2029)
 - STUN: fix Skype/MsTeams detection and monitoring logic (#2028)
 - STUN: fix detection of Google Voip apps (#2031)
 - STUN: fix detection over TCP
 - STUN: improve WhatsappCall detection
 - STUN: keep monitoring/processing STUN flows (#2012)
 - STUN: tell RTP from RTCP while in monitoring state (#2027)
 - Serialization fix
 - Set _DEFAULT_SOURCE and _GNU_SOURCE globally. (#2010)
 - Simplify `ndpi_internal_guess_undetected_protocol()` (#1941)
 - Simplify the report of streaming multimedia info (#2026)
 - SoftEther: fix invalid memory access
 - Swap from Aho-Corasick to an experimental/home-grown algorithm that uses a probabilistic approach for handling Internet domain names.
 - Sync unit tests results
 - Sync unit tests results
 - Sync unit tests results (#1962)
 - Sync utests results (#1887)
 - TLS: add basic, basic, detection of Encrypted ClientHello (#2053)
 - TLS: fix another interger overflow in certificate processing (#1915)
 - TLS: fix parsing of certificate elements (#1910)
 - Test files for riit games
 - Test multiple `ndpiReader` configurations (#1931)
 - Thrift: fix heap-buffer-overflow (#2024)
 - Update GitHub runners versions (#1889)
 - Update every ip lists (#2079)
 - Update libinjection code (#1918)
 - Update protocols documentation (#2081)
 - Update roaring bitmap code
 - Updated line test result
 - Updated pcap detection results after Facebook Reel/Stories support
 - Updated results
 - Updated results after the latest changes
 - Win include change
 - Windows code rework
 - Windows compilation fixes
 - Windows warning checks
 - add 2 ns from fdn.fr to DoH section (#1964)
 - add support for gre decapsulation (#1442) (#1921)
 - added bimap and/or with allocation
 - added feature to extract filename from http attachment (#2037)
 - added new domain names (#2002)
 - configure: add an option to enable debug build, i.e `-g` (#1929)
 - fix Stack overflow caused by invalid write in ndpi_automa_match_strin…  (#2035)
 - fixed numeric truncation error
 - fixed numeric truncation error in diameter.c (#2034)
 - fixed numeric truncation error in kerberos.c (#2032)
 - fixed numeric truncation error in ndpi_main.c:6837 (#1998)
 - fixed numeric truncation error in rtcp.c (#2033)
 - fuzz: add a new fuzzer to test TLS certificates (#1901)
 - fuzz: add a new fuzzer triggering the payload analyzer function(s) (#1926)
 - fuzz: add fuzzer for DGA detection code (#2042)
 - fuzz: add fuzzer to test internal gcrypt code (#1920)
 - fuzz: add fuzzers to test bitmap64 and domain_classify data structures (#2082)
 - fuzz: add fuzzers to test reader_util code (#2080)
 - fuzz: extend coverage (#2073)
 - fuzz: extend fuzz coverage (#1888)
 - fuzz: extend fuzzers coverage (#1952)
 - fuzz: extend fuzzing coverage (#2040)
 - fuzz: extend fuzzing coverage (#2052)
 - fuzz: extend fuzzing coverage (#2083)
 - fuzz: simplify fuzzers dependencies in CIFuzz (#1896)
 - fuzz: some improvements and add two new fuzzers (#1881)
 - fuzzing: extend fuzzing coverage
 - in case of failure, failing result files are not listed
 - minor fixes (#2023)
 - oss-fuzz: sync build script with upstream
 - remove redefinition to vxlanhdr struct in vxlan dissector (#1911)
 - removed useless call of ndpi_set_risk func (#2022)
 - tests: add an option to force the overwrite of the unit tests results (#2001)
 - tests: restore some old paths as symbolic links (#2050)
 - tftp: check for Option Acknowledgements
 - tftp: check incrementation for DATA and ACK packets
 - tftp: rework request checking to account for options
 - tftp: update pcap results
 - version of dirent.c that is liked by both VC++ and MinGW


#### nDPI 4.6 (Feb 2023)

## New Features
 
  - New support for custom BPF protocol definition using nBPF (see example/protos.txt)
  - Improved dissection performance
  - Added fuzzing all over

## New Supported Protocols and Services

 - Add protocol detection for:
   - Activision
   - AliCloud server access
   - AVAST
   - CryNetwork
   - Discord
   - EDNS
   - Elasticsearch
   - FastCGI
   - Kismet
   - Line App and Line VoIP calls
   - Meraki Cloud
   - Munin
   - NATPMP
   - Syncthing
   - TP-LINK Smart Home
   - TUYA LAN
   - SoftEther VPN
   - Tailscale
   - TiVoConnect

## Improvements

 - Improve protocol detection for:
   - Anydesk
   - Bittorrent (fix confidence, detection over TCP)
   - DNS, add ability to decode DNS PTR records used for reverse address resolution
   - DTLS (handle certificate fragments)
   - Facebook Voip calls
   - FastCGI (dissect PARAMS)
   - FortiClient (update default ports)
   - Zoom
     - Add Zoom screen share detection
     - Add detection of Zoom peer-to-peer flows in STUN
   - Hangout/Duo Voip calls detection, optimize lookups in the protocol tree
   - HTTP
     - Handling of HTTP-Proxy and HTTP-Connect
     - HTTP subclassification
     - Check for empty/missing user-agent in HTTP
   - IRC (credentials check)
   - Jabber/XMPP
   - Kerberos (support for Krb-Error messages)
   - LDAP
   - MGCP
   - MONGODB (avoid false positives)
   - Postgres
   - POP3
   - QUIC (support for 0-RTT packets received before the initial)
   - Snapchat Voip calls
   - SIP
   - SNMP
   - SMB (support for messages split into multiple TCP segments)
   - SMTP (support for X-ANONYMOUSTLS command)
   - STUN
   - SKYPE (improve detection over UDP, remove detection over TCP)
   - Teamspeak3 (License/Weblist detection)
   - Threema Messenger
   - TINC (avoid processing SYN packets)
   - TLS
     - improve reassembler
     - handling of ALPN(s) and subclassification
     - ignore invalid Content Type values
   - WindowsUpdate
 - Add flow risk:
   - NDPI_HTTP_OBSOLETE_SERVER
   - NDPI_MINOR_ISSUES (generic/relevant information about issues found on traffic)
   - NDPI_HTTP_OBSOLETE_SERVER (Apache and nginx are supported)
   - NDPI_PERIODIC_FLOW (reserved bit to be used by apps based on nDPI)
   - NDPI_TCP_ISSUES
 - Improve detection of WebShell and PHP code in HTTP URLs that is reported via flow risk
 - Improve DGA detection
 - Improve AES-NI check
 - Improve nDPI JSON serialization
 - Improve export/print of L4 protocol information
 - Improve connection refused detection
 - Add statistics for Patricia tree, Ahocarasick automa, LRU cache
 - Add a generic (optional and configurable) expiration logic in LRU caches
 - Add RTP stream type in flow metadata
 - LRU cache is now IPv6 aware

## Tools

 - ndpiReader
   - Add support for Linux Cooked Capture v2
   - Fix packet dissection (CAPWAP and TSO)
   - Fix Discarded bytes statistics

## Fixes

 - Fix classification by-port
 - Fix exclusion of DTLS protocol
 - Fix undefined-behaviour in ahocorasick callback
 - Fix infinite loop when a custom rule has port 65535
 - Fix undefined-behavior when setting empty user-agent
 - Fix infinite loop in DNS dissector (due to an integer overflow)
 - Fix JSON export of IPv6 addresses
 - Fix memory corruptions in Bittorrent, HTTP, SoftEther, Florensia, QUIC, IRC, TFTP dissectors
 - Fix stop of extra dissection in HTTP, Bittorrent, Kerberos
 - Fix signed integer overflow in ASN1/BER dissector
 - Fix char/uchar bug in ahocorasick
 - Fix endianness in IP-Port lookup
 - Fix FastCGI memory allocation issue
 - Fix metadata extraction in NAT-PMP
 - Fix invalid unidirectional traffic alert for unidirectional protocols (e.g. sFlow)

## Misc

 - Support for Rocky Linux 9
 - Enhance fuzzers to test nDPI configurations, memory allocation failures, serialization/deserialization, algorithms and data structures
 - GitHub Actions: update to Node.js 16
 - Size of LRU caches is now configurable

#### nDPI 4.4 (July 2022)

## New Features
 - Add risk information that describes why a specific risk was triggered also providing metadata
 - Added API call ndpi_check_flow_risk_exceptions() for handling risk exceptions
 - Split protocols in: network (e.g. TLS) and application protocols (e.g. Google)
 - Extended confidence level with two new values (NDPI_CONFIDENCE_DPI_PARTIAL and NDPI_CONFIDENCE_DPI_PARTIAL_CACHE)
 - Added ndpi_get_flow_error_code() API call

## New Supported Protocols and Services
 - Add protocol detection for:
   - UltraSurf
   - i3D
   - RiotGames
   - TSAN
   - TunnelBear VPN
   - collectd
   - PIM (Protocol Indipendent Multicast)
   - Pragmatic General Multicast (PGM)
   - RSH
   - GoTo products (mainly GoToMeeting)
   - Dazn
   - MPEG-DASH
   - Agora Software Defined Real-time Network (SD-RTN)
   - Toca Boca
   - VXLAN
   - MDNS/LLMNR

## Improvements
 - Improve protocol detection for:
   - SMTP/SMTPS now supports STARTTLS
   - OCSP
   - TargusDataspeed
   - Usenet
   - DTLS (added support for old versions)
   - TFTP
   - SOAP via HTTP
   - GenshinImpact
   - IPSec/ISAKMP
   - DNS
   - syslog
   - DHCP (various bug fixes and improvements)
   - NATS
   - Viber
   - Xiaomi
   - Raknet
   - gnutella
   - Kerberos
   - QUIC (Added support for v2drft 01)
   - SSDP
   - SNMP
 - Improved DGA detection
 - Improved AES-NI check
 - Add flow risk:
   - NDPI_PUNYCODE_IDN
   - NDPI_ERROR_CODE_DETECTED
   - NDPI_HTTP_CRAWLER_BOT
   - NDPI_ANONYMOUS_SUBSCRIBER
   - NDPI_UNIDIRECTIONAL_TRAFFIC

## Changes
 - Added support for 64 bit bins
 - Added Cloudflare WARP detection patterns
 - Renamed Z39.50 -> Z3950
 - Replaced nDPI's internal hashmap with uthash
 - Reimplemented 1kxun application protoco
 - Renamed SkypeCall to Skype_TeamsCall
 - Updated Python Bindings
 - Unless --with-libgcrypt is used, nDPI now uses its internal gcrypt implementation

## Fixes
 - Fixes for some protocol classification families
 - Fixed default protocol ports for email protocols
 - Various memory and overflow fixes
 - Disabled various risks for specific protocols (e.g. disable missing ALPN for CiscoVPN)
 - Fix TZSP decapsulation

## Misc
 - Update ASN/IPs lists
 - Improved code profiling
 - Use Doxygen to generate the API documentation
 - Added Edgecast and Cachefly CDNs.

#### nDPI 4.2 (Feb 2022)

## New Features
 - Add a "confidence" field indicating the reliability of the classification
 - Add risk exceptions for services and domain names via ndpi_add_domain_risk_exceptions()
 - Add ability to report whether a protocol is encrypted

## New Supported Protocols and Services
 - Add protocol detection for:
   - Badoo
   - Cassandra
   - EthernetIP

## Improvements
 - Reduce memory footprint
 - Improve protocol detection for:
   - BitTorrent
   - ICloud Private Relay
   - IMAP, POP3, SMTP
   - Log4J/Log4Shell
   - Microsoft Azure
   - Pandora TV
   - RTP
   - RTSP
   - Salesforce
   - STUN
   - Whatsapp
   - QUICv2
   - Zoom
 - Add flow risk:
   - NDPI_CLEAR_TEXT_CREDENTIALS
   - NDPI_POSSIBLE_EXPLOIT (Log4J)
   - NDPI_TLS_FATAL_ALERT
   - NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE
 - Update WhatsAPP and Instagram addresses
 - Update the list of default ports for QUIC
 - Update WindowsUpdate URLs 
 - Add support for the .goog Google TLD
 - Add googletagmanager.com
 - Add bitmaps and API for handling compressed bitmaps
 - Add JA3 in risk exceptions
 - Add entropy calculation to check for suspicious (encrypted) payload
 - Add extraction of hostname in SMTP
 - Add RDP over UDP dissection
 - Add support for TLS over IPV6 in Subject Alt Names field
 - Improve JSON and CSV serialization
 - Improve IPv6 support for almost all dissectors
 - Improve CI and unit tests, add arm64, armhf and s390x as part of CI
 - Improve WHOIS detection, reduce false positives
 - Improve DGA detection for skipping potential DGAs of known/popular domain names
 - Improve user agent analysis
 - Reworked HTTP protocol dissection including HTTP proxy and HTTP connect

## Changes
 - TLS obsolete protocol is set when TLS < 1.2 (used to be 1.1)
 - Numeric IPs are not considered for DGA checks
 - Differentiate between standard Amazon stuff (i.e market) and AWS
 - Remove Playstation VUE protocol
 - Remove pandora.tv from Pandora protocol
 - Remove outdated SoulSeek dissector

## Fixes
 - Fix race conditions
 - Fix dissectors to be big-endian friendly
 - Fix heap overflow in realloc wrapper
 - Fix errors in Kerberos, TLS, H323, Netbios, CSGO, Bittorrent
 - Fix wrong tuple comparison
 - Fix ndpi_serialize_string_int64
 - Fix Grease values parsing
 - Fix certificate mismatch check
 - Fix null-dereference read for Zattoo with IPv6
 - Fix dissectors initialization for XBox, Diameter
 - Fix confidence for STUN classifications
 - Fix FreeBSD support
 - Fix old GQUIC versions on big-endian machines
 - Fix aho-corasick on big-endian machines
 - Fix DGA false positive
 - Fix integer overflow for QUIC
 - Fix HTTP false positives
 - Fix SonarCloud-CI support
 - Fix clashes setting the hostname on similar protocols (FTP, SMTP)
 - Fix some invalid TLS guesses
 - Fix crash on ARM (Raspberry)
 - Fix DNS (including fragmented DNS) dissection
 - Fix parsing of IPv6 packets with extension headers
 - Fix extraction of Realm attribute in STUN
 - Fix support for START-TLS sessions in FTP
 - Fix TCP retransmissions for multiple dissectors
 - Fix DES initialisation
 - Fix Git protocol dissection
 - Fix certificate mismatch for TLS flows with no client hello observed
 - Fix old versions of GQUIC on big-endian machines

## Misc
 - Add tool for generating automatically the Azure IP list

#### nDPI 4.0 (July 2021)

## New Features
 - Add API for computing RSI (Relative Strenght Index)
 - Add GeoIP support
 - Add fragments management
 - Add API for jitter calculation
 - Add single exponential smoothing API
 - Add timeseries forecasting support implementing Holt-Winters with confidence interval
 - Add support for MAC to radi tree and expose the full API to applications
 - Add JA3+, with ALPN and elliptic curve
 - Add double exponential smoothing implementation
 - Extended API for managing flow risks
 - Add flow risk score
 - New flow risks:
   - Desktop or File Sharing Session
   - HTTP suspicious content (useful for tracking trickbot)
   - Malicious JA3
   - Malicious SHA1
   - Risky domain
   - Risky AS
   - TLS Certificate Validity Too Long
   - TLS Suspicious Extension

## New Supported Protocols and Services
 - New protocols:
   - AmongUs
   - AVAST SecureDNS
   - CPHA (CheckPoint High Availability Protocol)
   - DisneyPlus
   - DTLS
   - Genshin Impact
   - HP Virtual Machine Group Management (hpvirtgrp)
   - Mongodb
   - Pinterest
   - Reddit
   - Snapchat VoIP calls
   - Tumblr
   - Virtual Asssitant (Alexa, Siri)
   - Z39.50
 - Add protocols to HTTP as subprotocols
 - Add detection of TLS browser type
 - Add connectionless DCE/RPC detection

## Improvements
   - 2.5x speed bump. Example ndpiReader with a long mixed pcap
	v3.4 - nDPI throughput:       1.29 M pps / 3.35 Gb/sec
	v4.0 - nDPI throughput:       3.35 M pps / 8.68 Gb/sec
  - Improve detection/dissection of:
   - AnyDesk
   - DNS
   - Hulu
   - DCE/RPC (avoid false positives)
   - dnscrypt
   - Facebook (add new networks)
   - Fortigate
   - FTP Control
   - HTTP
     - Fix user-agent parsing
     - Fix logs when NDPI_ENABLE_DEBUG_MESSAGES is defined
   - IEC104
   - IEC60870
   - IRC
   - Netbios
   - Netflix
   - Ookla speedtest (detection over IPv6)
   - openspeedtest.com
   - Outlook / MicrosoftMail
   - QUIC
     - update to draft-33
     - improve handling of SNI
     - support for fragmented Client Hello
     - support for DNS-over-QUIC
   - RTSP
   - RTSP via HTTP
   - SNMP (reimplemented)
   - Skype
   - SSH
   - Steam (Steam Datagram Relay - SDR)
   - STUN (avoid false positives, improved Skype detection)
   - TeamViewer (add new hosts)
   - TOR (update hosts)
   - TLS
     - Certificate Subject matching
     - Check for common ALPNs
     - Reworked fingerprint calculation
     - Fix extraction for TLS signature algorithms
     - Fix ClientHello parsing
   - UPnP
   - wireguard
 - Improve DGA detection
 - Improve JA3
 - Improve Mining detection
 - Improve string matching algorithm
 - Improve ndpi_pref_enable_tls_block_dissection
 - Optimize speed and memory size
 - Update ahocorasick library
 - Improve subprotocols detection

## Fixes
 - Fix partial application matching
 - Fix multiple segfault and leaks
 - Fix uninitialized memory use
 - Fix release of patterns allocated in ndpi_add_string_to_automa
 - Fix return value of ndpi_match_string_subprotocol
 - Fix setting of flow risks on 32 bit machines
 - Fix TLS certificate threshold
 - Fix a memory error in TLS JA3 code
 - Fix false positives in Z39.50
 - Fix off-by-one memory error for TLS-JA3
 - Fix bug in ndpi_lru_find_cache
 - Fix invalid xbox and playstation port guesses
 - Fix CAPWAP tunnel decoding
 - Fix parsing of DLT_PPP datalink type
 - Fix dissection of QUIC initial packets coalesced with 0-RTT one
 - Fix parsing of GTP headers
 - Add bitmap boundary checks

## Misc
 - Update download category name
 - Update category labels
 - Renamed Skype in Skype_Teams (the protocol is now shared across these apps)
 - Add IEC analysis wireshark plugin
 - Flow risk visualization in Wireshark
 - ndpiReader
   - add statistics about nDPI performance
   - fix memory leak
   - fix collecting of risks statistics
 - Move installed libraries from /usr/local to /usr
 - Improve NDPI_API_VERSION generation
 - Update ndpi_ptree_match_addr prototype

#### nDPI 3.4 (October 2020)

## New Features
* Completely reworked and extended QUIC dissector
* Added flow risk concept to move nDPI towards result interpretation
* Added ndpi_dpi2json() API call
* Added DGA risk for names that look like a DGA
* Added HyperLogLog cardinality estimator API calls
* Added ndpi_bin_XXX API calls to handle bin handling
* Fully fuzzy tested code that has greatly improved reliability and robustness

## New Supported Protocols and Services
* QUIC
* SMBv1
* WebSocket
* TLS: added ESNI support
* SOAP
* DNScrypt

## Improvements
* Python CFFI bindings
* Various TLS extensions and fixes including extendede metadata support
* Added various pcap files for testing corner cases in protocols
* Various improvements in JSON/Binary data serialization
* CiscoVPN
* H323
* MDNS
* MySQL 8
* IEC 60870-5-104
* DoH/DoT dissection improvements
* Office365 renamed to Microsoft365
* Major protocol dissection improvement in particular with unknwon traffic
* Improvement in Telegram v6 protocol support
* HTTP improvements to detect file download/upload and binary files
* BitTorrent and WhatsApp dissection improvement
* Spotify
* Added detection of malformed packets
* Fuzzy testing support has been greatly improved
* SSH code cleanup

## Fixes
* Fixed various memory leaks and race conditions in protocol decoding
* NATS, CAPWAP dissector
* Removed HyperScan support that greatly simplified the code
* ARM platform fixes on memory alignment
* Wireshark extcap support
* DPDK support
* OpenWRT, OpenBSD support
* MINGW compiler support

## MISC
* Created demo app for nDPI newcomers
* Removed obsolete pplive and pando protocols

#### nDPI 3.2 (February 2020)

## New Features
* New API calls
  * Protocol detection: ndpi_is_protocol_detected
  * Categories: ndpi_load_categories_file / ndpi_load_category
  * JSON/TLV serialization: ndpi_serialize_string_boolean / ndpi_serialize_uint32_boolean
  * Patricia tree: ndpi_load_ipv4_ptree
  * Module initialization: ndpi_init_detection_module / ndpi_finalize_initalization
  * Base64 encoding: ndpi_base64_encode
  * JSON exprot: ndpi_flow2json
  * Print protocol: ndpi_get_l4_proto_name / ndpi_get_l4_proto_info
* Libfuzz integration
* Implemented Community ID hash (API call ndpi_flowv6_flow_hash and ndpi_flowv4_flow_hash)
* Detection of RCE in HTTP GET requests via PCRE
* Integration of the libinjection library to detect SQL injections and XSS type attacks in HTTP requests

## New Supported Protocols and Services
* TLS
  * Added ALPN support
  * Added export of supported version in TLS header
* Added Telnet dissector with metadata extraction
* Added Zabbix dissector
* Added POP3/IMAP metadata extraction
* Added FTP user/password extraction
* Added NetBIOS metadata extraction
* Added Kerberos metadata extraction
* Implemented SQL Injection and XSS attack detection
* Host-based detection improvements and changes
  * Added Microsoft range
  * Added twitch.tv website
  * Added brasilbandalarga.com.br and .eaqbr.com.br as EAQ
  * Added 20.180.0.0/14, 20.184.0.0/13 range as Skype
  * Added 52.84.0.0/14 range as Amazon
  * Added ^pastebin.com
  * Changed 13.64.0.0/11 range from Skype to Microsoft
  * Refreshed Whatsapp server list, added *whatsapp-*.fbcdn.net IPs
* Added public DNSoverHTTPS servers

## Improvements
* Reworked and improved the TLS dissector
* Reworked Kerberos dissector
* Improved DNS response decoding
* Support for DNS continuous flow dissection
* Improved Python bindings
* Improved Ethereum support
* Improved categories detection with streaming and HTTP
* Support for IP-based detection to compute the application protocol
* Renamed protocol 104 to IEC60870 (more meaningful)
* Added failed authentication support with FTP
* Renamed DNSoverHTTPS to handle bot DoH and DoT
* Implemented stacked DPI decoding
* Improvements for CapWAP and Bloomberg
* Improved SMB dissection
* Improved SSH dissection
* Added capwap support
* Modified API signatures for ndpi_ssl_version2str / ndpi_detection_giveup
* Removed ndpi_pref_http_dont_dissect_response / ndpi_pref_dns_dont_dissect_response (replaced by ndpi_extra_dissection_possible)

## Fixes
* Fixed memory invalid access in SMTP and leaks in TLS
* Fixed a few memory leaks
* Fixrd invalid memory access in a few protocol dissectors (HTTP, memcached, Citrix, STUN, DNS, Amazon Video, TLS, Viber)
* Fixed IPv6 address format across the various platforms/distributions
* Fixed infinite loop in ndpi_workflow_process_packet
* Fixed SHA1 certificate detection
* Fixed custom protocol detection
* Fixed SMTP dissection (including email)
* Fixed Telnet dissection and invalid password report
* Fixed invalid category matching in HTTP
* Fixed Skype and STUN false positives
* Fixed SQL Injection detection
* Fixed invalid SMBv1 detection
* Fixed SSH dissection
* Fixed ndpi_ssl_version2str
* Fixed ndpi_extra_dissection_possible
* Fixed out of bounds read in ndpi_match_custom_category

## Misc
* ndpiReader
  * CSV output enhancements
  * Added tunnelling decapsulation
  * Improved HTTP reporting

------------------------------------------------------------------------

#### nDPI 3.0 (October 2019)

## New Features
* nDPI now reports the protocol ASAP even when specific fields have not yet been dissected because such packets have not yet been observed. This is important for inline applications that can immediately act on traffic. Applications that need full dissection need to call the new API function ndpi_extra_dissection_possible() to check if metadata dissection has been completely performed or if there is more to read before declaring it completed.
* TLS (formerly identified as SSL in nDPI v2.x) is now dissected more deeply, certificate validity is extracted as well certificate SHA-1.
* nDPIreader can now export data in CSV format with option `-C`
* Implemented Sequence of Packet Length and Time (SPLT) and Byte Distribution (BD) as specified by Cisco Joy (https://github.com/cisco/joy). This allows malware activities on encrypted TLS streams. Read more at https://blogs.cisco.com/security/detecting-encrypted-malware-traffic-without-decryption
  * Available as library and in `ndpiReader` with option `-J`
* Promoted usage of protocol categories rather than protocol identifiers in order to classify protocols. This allows application protocols to be clustered in families and thus better managed by users/developers rather than using hundred of protocols unknown to most of the people.
* Added Inter-Arrival Time (IAT) calculation used to detect protocol misbehaviour (e.g. slow-DoS detection)
* Added data analysis features for computign metrics such as entropy, average, stddev, variance on a single and consistent place that will prevent when possible. This should ease traffic analysis on monitoring/security applications. New API calls have been implemented such as ndpi_data_XXX() to handle these calculations.
* Initial release of Python bindings available under nDPI/python.
* Implemented search of human readable strings for promoting data exfiltration detection
  * Available as library and in `ndpiReader` with option `-e`
* Fingerprints
  * JA3 (https://github.com/salesforce/ja3)
  * HASSH (https://github.com/salesforce/hassh)
  * DHCP
* Implemented a library to serialize/deserialize data in both Type-Length-Value (TLV) and JSON format
  * Used by nProbe/ntopng to exchange data via ZMQ

## New Supported Protocols and Services

* DTLS (i.e. TLS over UDP)
* Hulu
* TikTok/Musical.ly
* WhatsApp Video
* DNSoverHTTPS
* Datasaver
* Line protocol
* Google Duo and Hangout merged
* WireGuard VPN
* IMO
* Zoom.us

## Improvements

* TLS
  * Organizations
  * Ciphers
  * Certificate analysis
* Added PUBLISH/SUBSCRIBE methods to SIP
* Implemented STUN cache to enhance matching of STUN-based protocols
* Dissection improvements
  * Viber
  * WhatsApp
  * AmazonVideo
  * SnapChat
  * FTP
  * QUIC
  * OpenVPN support for UDP-based VPNs
  * Facebook Messenger mobile
  * Various improvements for STUN, Hangout and Duo
* Added new categories: CUSTOM_CATEGORY_ANTIMALWARE, NDPI_PROTOCOL_CATEGORY_MUSIC, NDPI_PROTOCOL_CATEGORY_VIDEO, NDPI_PROTOCOL_CATEGORY_SHOPPING, NDPI_PROTOCOL_CATEGORY_PRODUCTIVITY and NDPI_PROTOCOL_CATEGORY_FILE_SHARING
* Added NDPI_PROTOCOL_DANGEROUS classification

## Fixes

* Fixed the dissection of certain invalid DNS responses
* Fixed Spotify dissection
* Fixed false positives with FTP and FTP_DATA
* Fix to discard STUN over TCP flows
* Fixed MySQL dissector
* Fix category detection due to missing initialization
* Fix DNS rsp_addr missing in some tiny responses
* Various hardening fixes

------------------------------------------------------------------------

#### nDPI 2.8 (March 2019)

## New Supported Protocols and Services

* Added Modbus over TCP dissector

## Improvements

* Wireshark Lua plugin compatibility with Wireshark 3
* Improved MDNS dissection
* Improved HTTP response code handling
* Full dissection of HTTP responses

## Fixes

* Fixed false positive mining detection
* Fixed invalid TCP DNS dissection
* Releasing buffers upon `realloc` failures
* ndpiReader: Prevents references after free
* Endianness fixes
* Fixed IPv6 HTTP traffic dissection
* Fixed H.323 detection

## Other

* Disabled ookla statistics which need to be improved
* Support for custom protocol files of arbitrary length
* Update radius.c to RFC2865

------------------------------------------------------------------------

#### nDPI 2.6 (December 2018)

## New Supported Protocols and Services

* New Bitcoin, Ethereum, ZCash, Monero dissectors all identified as Mining
* New Signal.org dissector
* New Nest Log Sink dissector
* New UPnP dissector
* Added support for SMBv1 traffic, split from SMBv23

## Improvements

* Improved Skype detection, merged Skype call in/out into Skype Call
* Improved heuristics for Skype, Teredo, Netbios
* Improved SpeedTest (Ookla) detection
* Improved WhatsApp detection
* Improved WeChat detection
* Improved Facebook Messenger detection
* Improved Messenger/Hangout detection
* Improved SSL detection, prevent false positives
* Improved guess for UDP protocols
* Improved STUN detection
* Added more Ubuntu servers
* Added missing categorization with giveup/guess
* Optimizations for TCP flows that do not start with a SYN packet (early giveup)

## Fixes

* Fixed eDonkey false positives
* Fixed Dropbox dissector
* Fixed Spotify dissector
* Fixed custom protocol loading
* Fixed missing Application Data packet for TLS
* Fixed buffer overflows
* Fixed custom categories match by IP
* Fixed category field not accounted in ndpi_get_proto_category
* Fixed null pointer dereference in ndpi_detection_process_packet
* Fixed compilation on Mac

## Other

* Deb and RPM packages: ndpi with shared libraries and binaries, ndpi-dev with headers and static libraries
* Protocols now have an optional subprotocol: Spotify cannot have subprotocols, DNS can (DNS.Spotify)
* New API functions:
 * ndpi_fill_ip_protocol_category to handle ICMP flows category
 * ndpi_flowv4_flow_hash and ndpi_flowv6_flow_hash to support the Community ID Flow Hashing (https://github.com/corelight/community-id-spec)
 * ndpi_protocol2id to print the protocol as ID
 * ndpi_get_custom_category_match to search host in custom categories
* Changed ndpi_detection_giveup API: guess is now part of the call
* Added DPDK support to ndpiReader
* Removed Musical.ly protocol (service no longer used)
* Custom categories have now priority over protocol related categories
* Improved clang support

------------------------------------------------------------------------

#### nDPI 2.4 (August 2018)

## New Supported Protocols and Services

* Showmax.com
* Musical.ly
* RapidVideo
* VidTO streaming service
* Apache JServ Protocol
* Facebook Messenger
* FacebookZero protocol

## Improvements

* Improved YouTube support
* Improved Netflix support
* Updated Google Hangout detection
* Updated Twitter address range
* Updated Viber ports, subnet and domain
* Updated AmazonVideo detection
* Updated list of FaceBook sites
* Initial Skype in/out support
* Improved Tor detection
* Improved hyperscan support and category definition
* Custom categories loading, extended ndpiReader (`-c <file>`) for loading name-based categories

## Fixes

* Fixes for Instagram flows classified as Facebook
* Fixed Spotify detection
* Fixed minimum packet payload length for SSDP
* Fixed length check in MSN, x-steam-sid, Tor certificate name
* Increase client's maximum payload length for SSH
* Fixed end-of-line bounds handling
* Fixed substring matching
* Fix for handling IP address based custom categories
* Repaired wrong timestamp calculation
* Fixed memory leak
* Optimized memory usage

## Other/Changes

* New API calls:
  * `ndpi_set_detection_preferences()`
  * `ndpi_load_hostname_category()`
  * `ndpi_enable_loaded_categories()`
  * `ndpi_fill_protocol_category()`
  * `ndpi_process_extra_packet()`
* Skype CallIn/CallOut are now set as Skype.SkypeCallOut Skype.SkypeCallIn
* Added support for SMTPS on port 587
* Changed RTP from VoIP to Media category
* Added site unavailable category
* Added custom categories CUSTOM_CATEGORY_MINING, CUSTOM_CATEGORY_MALWARE, CUSTOM_CATEGORY_ADVERTISEMENT, CUSTOM_CATEGORY_BANNED_SITE
* Implemented hash-based categories
* Converted some not popular protocols to NDPI_PROTOCOL_GENERIC with category detection

------------------------------------------------------------------------

#### nDPI 2.2.2 (April 2018)

## Main New Features

* Hyperscan support
* `ndpi_get_api_version` API call to be used in applications that are dynamically linking with nDPI
* `--enable-debug-messages` to enable debug information output
* Increased number of protocols to 512

## New Supported Protocols and Services

* GoogleDocs
* GoogleServices
* AmazonVideo
* ApplePush
* Diameter
* GooglePlus
* WhatsApp file exchage

## Improvements

* WhatsApp detection
* Amazon detection
* Improved Google Drive
* Improved Spotify support
* Improved SNI matching when using office365
* Improved HostShield VPN

## Fixes

* Fixed invalid RTP/Skype detection
* Fixed possible out-of-bounds due to malformed DHCP packets
* Fixed buffer overflow in function `ndpi_debug_printf`

------------------------------------------------------------------------

#### nDPI 2.2 (December 2017)

## Main New Features

* Custom protocol categories to allow personalization of protocols-categories mappings
* DHCP fingerprinting
* HTTP User Agent discovery


## New Supported Protocols and Services

* ICQ (instant messaging client)
* YouTube Upload
* LISP
* SoundCloud
* Sony PlayStation
* Nintendo (switch) gaming protocol


## Improvements

*  Windows 10 detection from UA and indentation
*  Determine STUN flows that turn into RTP
*  Fixes for iQIYI and 1kxun
*  Android fingerprint
*  Added DHCP class identifier support

------------------------------------------------------------------------

#### nDPI 2.0 (May 2017)

## Main New Features

* nDPI Wireshark plugin for Layer-7 protocol dissection. The plugin, available via an extcap interface, passes Wireshark the nDPI-detected protocols by adding an ethernet packet trailer that is then interpreted and displayed inside the Wireshark GUI. Readme: https://github.com/ntop/nDPI/blob/dev/wireshark/README.md


## New Supported Protocols and Services

* STARTTLS
* IMAPS
* DNScrypt
* QUIC (Quick UDP Internet Connections)
* AMQP (Advanced Message Queueing Protocol)
* Ookla (SpeedTest)
* BJNP
* AFP (Apple Filing Protocol)
* SMPP (Short Message Peer-to-Peer)
* VNC
* OpenVPN
* OpenDNS
* RX protocol (used by AFS)
* CoAP and MQTT (IoT specific protocols)
* Cloudflare
* Office 365
* OCS
* MS Lync
* Ubiquity AirControl 2
* HEP (Extensible Encapsulation Protocol)
* WhatsApp Voice vs WhatsApp (chat, no voice)
* Viber
* Wechat
* Github
* Hotmail
* Slack
* Instagram
* Snapchat
* MPEG TS protocol
* Twitch
* KakaoTalk Voice and Chat
* Meu
* EAQ
* iQIYI media service
* Weibo
* PPStream


## Improvements

* SSH client/server version dissection
* Improved SSL dissection
* SSL server certificate detection
* Added double tagging 802.1Q in dissection of vlan-tagged packets
* Improved netBIOS dissection
* Improved Skype detection
* Improved Netflix traffic detection
* Improved HTTP subprotocol matching
* Implemented DHCP host name extraction
* Updated Facebook detection by ip server ranges
* Updated Twitter networks
* Improved Microsoft detection
* Enhanced Google detection
* Improved BT-uTP protocol dissection
* Added detection of Cisco datalink layer (Cisco hDLC and Cisco SLARP)


#### Older releases

#### 2014-03-21
* improved support for eDonkey/eMule/Kademlia
* improved support for PPLive

#### 2014-03-20
* code optimizations
* consistency improvements
* added support for new applications: Pando Media Booster
* improved support for Steam
* added support for new web services: Wikipedia, MSN, Amazon, eBay, CNN

#### 2014-03-19
* added new protocols: FTP, code improvements

#### 2014-03-17
* added new protocols: SOCKSv4, SOCKSv5, RTMP
