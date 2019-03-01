# CHANGELOG

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
  - ndpi_fill_ip_protocol_category to handle ICMP flows category
  - ndpi_flowv4_flow_hash and ndpi_flowv6_flow_hash to support the Community ID Flow Hashing (https://github.com/corelight/community-id-spec)
  - ndpi_protocol2id to print the protocol as ID
  - ndpi_get_custom_category_match to search host in custom categories
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
