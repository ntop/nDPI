nDPI Protocols List
###################

This page provides the list of the protocols/applications supported by nDPI. For each protocol there is a brief description, some links to further, more detailed information and, optionally, some notes that might be useful when handling such a protocol (from the application/integrator point of view)

Work in progress!


.. _Proto_1:

`NDPI_PROTOCOL_FTP_CONTROL`
===========================
FTP Control protocol used for managing file transfers between client and server.

References: `RFC959: <https://datatracker.ietf.org/doc/html/rfc959>`_


.. _Proto_2:

`NDPI_PROTOCOL_MAIL_POP`
========================
POP (Post Office Protocol) is used by email clients to retrieve messages from a mail server.

References: `RFC1939: <https://datatracker.ietf.org/doc/html/rfc1939>`_


.. _Proto_3:

`NDPI_PROTOCOL_MAIL_SMTP`
=========================
SMTP (Simple Mail Transfer Protocol) is the standard protocol for sending email across the Internet.

References: `RFC5321: <https://datatracker.ietf.org/doc/html/rfc5321>`_


.. _Proto_4:

`NDPI_PROTOCOL_MAIL_IMAP`
=========================
IMAP (Internet Message Access Protocol) allows email clients to access and manipulate messages on a mail server.

References: `RFC3501: <https://datatracker.ietf.org/doc/html/rfc3501>`_


.. _Proto_5:

`NDPI_PROTOCOL_DNS`
====================
DNS (Domain Name System) translates human-friendly domain names to IP addresses.

References: `RFC1035: <https://datatracker.ietf.org/doc/html/rfc1035>`_


.. _Proto_6:

`NDPI_PROTOCOL_IPP`
===================
IPP (Internet Printing Protocol) is used for managing print jobs and queues over a network.

References: `RFC8010: <https://datatracker.ietf.org/doc/html/rfc8010>`_


.. _Proto_7:

`NDPI_PROTOCOL_HTTP`
====================
HTTP (Hypertext Transfer Protocol) is the foundation of data communication for the World Wide Web.

References: `RFC2616: <https://datatracker.ietf.org/doc/html/rfc2616>`_, `RFC7230: <https://datatracker.ietf.org/doc/html/rfc7230>`_


.. _Proto_8:

`NDPI_PROTOCOL_MDNS`
====================
mDNS (Multicast DNS) resolves hostnames to IP addresses within small networks without a local DNS server.

References: `RFC6762: <https://datatracker.ietf.org/doc/html/rfc6762>`_


.. _Proto_9:

`NDPI_PROTOCOL_NTP`
===================
NTP (Network Time Protocol) synchronizes clocks of computer systems over packet-switched datalinks.

References: `RFC5905: <https://datatracker.ietf.org/doc/html/rfc5905>`_


.. _Proto_10:

`NDPI_PROTOCOL_NETBIOS`
=======================
NetBIOS (Network Basic Input/Output System) provides services related to the session layer allowing applications on separate computers to communicate.

References: `Microsoft NetBIOS documentation: <https://learn.microsoft.com/en-us/previous-versions/windows/desktop/netbios/netbios-reference>`_


.. _Proto_11:

`NDPI_PROTOCOL_NFS`
===================
NFS (Network File System) allows a user on a client computer to access files over a network much like local storage.

References: `RFC7530: <https://datatracker.ietf.org/doc/html/rfc7530>`_


.. _Proto_12:

`NDPI_PROTOCOL_SSDP`
====================
SSDP (Simple Service Discovery Protocol) is used for advertising and discovering network services and presence information.

References: `RFC4861: <https://datatracker.ietf.org/doc/html/rfc4861>`_


.. _Proto_13:

`NDPI_PROTOCOL_BGP`
===================
BGP (Border Gateway Protocol) manages how packets are routed across the internet through the exchange of routing information.

References: `RFC4271: <https://datatracker.ietf.org/doc/html/rfc4271>`_


.. _Proto_14:

`NDPI_PROTOCOL_SNMP`
====================
SNMP (Simple Network Management Protocol) is used for collecting and organizing information about managed devices on IP networks.

References: `RFC1157: <https://datatracker.ietf.org/doc/html/rfc1157>`_


.. _Proto_15:

`NDPI_PROTOCOL_XDMCP`
=====================
XDMCP (X Display Manager Control Protocol) enables remote graphical logins to Unix/Linux systems.

References: `RFC1076: <https://datatracker.ietf.org/doc/html/rfc1076>`_


.. _Proto_16:

`NDPI_PROTOCOL_SMBV1`
=====================
SMBv1 (Server Message Block version 1) is a network file sharing protocol used for providing shared access to files and printers.

References: `Protocol Specs: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb>`_


.. _Proto_17:

`NDPI_PROTOCOL_SYSLOG`
======================
Syslog is a standard protocol used for message logging in an IP network.

References: `RFC5424: <https://datatracker.ietf.org/doc/html/rfc5424>`_


.. _Proto_18:

`NDPI_PROTOCOL_DHCP`
====================
DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses to devices in a network.

References: `RFC2131: <https://datatracker.ietf.org/doc/html/rfc2131>`_


.. _Proto_19:

`NDPI_PROTOCOL_POSTGRES`
========================
PostgreSQL is an advanced open-source relational database management system.

References: `PostgreSQL official site: <https://www.postgresql.org/>`_


.. _Proto_20:

`NDPI_PROTOCOL_MYSQL`
=====================
MySQL is a popular open-source relational database management system.

References: `MySQL official site: <https://www.mysql.com/>`_


.. _Proto_21:

`NDPI_PROTOCOL_MS_OUTLOOK`
==========================
Microsoft Outlook is an email client and personal information manager by Microsoft.

References: `Outlook official site: <https://outlook.live.com/>`_


.. _Proto_22:

`NDPI_PROTOCOL_VK`
==================
VK (VKontakte) is a Russian online social media and social networking service.

References: `VK official site: <https://vk.com/>`_


.. _Proto_23:

`NDPI_PROTOCOL_MAIL_POPS`
=========================
POPS (POP Secure) is POP protocol used over SSL/TLS for secure email retrieval.

References: `RFC2595: <https://datatracker.ietf.org/doc/html/rfc2595>`_


.. _Proto_24:

`NDPI_PROTOCOL_TAILSCALE`
=========================
Tailscale is a zero-config VPN based on WireGuard, simplifying secure network connectivity.

References: `Tailscale official site: <https://tailscale.com/>`_


.. _Proto_25:

`NDPI_PROTOCOL_YANDEX`
=======================
Yandex is a Russian internet company providing multiple online services including search.

References: `Yandex official site: <https://yandex.com/>`_


.. _Proto_26:

`NDPI_PROTOCOL_NTOP`
====================
ntop is a network traffic probe that shows network usage.

References: `ntop official site: <https://www.ntop.org/>`_


.. _Proto_27:

`NDPI_PROTOCOL_COAP`
====================
CoAP (Constrained Application Protocol) is a specialized web transfer protocol for use with constrained devices.

References: `RFC7252: <https://datatracker.ietf.org/doc/html/rfc7252>`_


.. _Proto_28:

`NDPI_PROTOCOL_VMWARE`
======================
VMware protocol used for management and data exchange in VMware virtualization platforms.

References: `VMware official site: <https://www.vmware.com/>`_


.. _Proto_29:

`NDPI_PROTOCOL_MAIL_SMTPS`
==========================
SMTPS (SMTP Secure) is SMTP protocol for sending emails over SSL/TLS encrypted connections.

References: `RFC2487: <https://datatracker.ietf.org/doc/html/rfc2487>`_


.. _Proto_30:

`NDPI_PROTOCOL_DTLS`
====================
DTLS (Datagram Transport Layer Security) provides communications privacy for datagram protocols.

References: `RFC6347: <https://datatracker.ietf.org/doc/html/rfc6347>`_


.. _Proto_31:

`NDPI_PROTOCOL_UBNTAC2`
=======================
AirControl network management application by Ubiquiti Networks.

References: `Ubiquiti AirControl community post: <https://community.ui.com/questions/Introduction-to-airControl/7cdb2648-113c-480f-b000-659b803d1afe/>`_


.. _Proto_32:

`NDPI_PROTOCOL_BFCP`
====================
BFCP (Binary Floor Control Protocol) is used for controlling and coordinating real-time data sharing and collaboration during video conferencing sessions.

References: `RFC8855: <https://datatracker.ietf.org/doc/html/rfc8855>`_


.. _Proto_33:

`NDPI_PROTOCOL_YANDEX_MAIL`
===========================
Yandex.Mail is a free email service provided by the Russian internet company Yandex.

References: `Yandex.Mail official site: <https://mail.yandex.com/>`_


.. _Proto_34:

`NDPI_PROTOCOL_YANDEX_MUSIC`
============================
Yandex.Music is a music streaming service offering a large library of tracks and personalized recommendations.

References: `Yandex.Music official site: <https://music.yandex.com/>`_


.. _Proto_35:

`NDPI_PROTOCOL_GNUTELLA`
========================
Gnutella is a decentralized peer-to-peer network protocol used for file sharing.

References: `Gnutella Wikipedia article: <https://en.wikipedia.org/wiki/Gnutella>`_


.. _Proto_36:

`NDPI_PROTOCOL_EDONKEY`
=======================
eDonkey is a peer-to-peer file sharing network popular in the early 2000s, supporting large file transfers.

References: `eDonkey Wikipedia article: <https://en.wikipedia.org/wiki/EDonkey_network>`_


.. _Proto_37:

`NDPI_PROTOCOL_BITTORRENT`
==========================
BitTorrent is a widely used peer-to-peer protocol for distributing large amounts of data efficiently.

References: `BitTorrent Wikipedia article: <https://en.wikipedia.org/wiki/BitTorrent>`_


.. _Proto_38:

`NDPI_PROTOCOL_MSTEAMS_CALL`
============================
Audio/video calls made by Microsoft applications, mainly MS Teams and Skype.

References: `Microsoft Teams official site: <https://www.microsoft.com/it-it/microsoft-teams/group-chat-software>`_


.. _Proto_39:

`NDPI_PROTOCOL_SIGNAL`
======================
Signal is a secure messaging protocol known for end-to-end encryption of texts and calls.

References: `Signal: <https://signal.org/>`_     


.. _Proto_40:

`NDPI_PROTOCOL_MEMCACHED`
=========================
Memcached is a distributed memory caching system used to speed up dynamic web applications.

References: `Memcached official site: <https://memcached.org/>`_


.. _Proto_41:

`NDPI_PROTOCOL_SMBV23`
======================
SMB version 2 and 3 are protocols for shared access to files, printers, and serial ports over a network.

References: `Server Message Block Wikipedia article: <https://en.wikipedia.org/wiki/Server_Message_Block>`_


.. _Proto_42:

`NDPI_PROTOCOL_MINING`
======================
Mining protocols enable communication with blockchain networks like Ethereum, ZCash, and Monero during cryptocurrency mining.

References: `Cryptocurrency Wikipedia article: <https://en.wikipedia.org/wiki/Cryptocurrency>`_


.. _Proto_43:

`NDPI_PROTOCOL_NEST_LOG_SINK`
=============================
Nest Log Sink protocol used by Nest Protect and other Nest devices (particularly smoke detectors) to send logging data.

References: `Nest Protect overview: <https://nest.com/smoke-co-alarm/overview/>`_


.. _Proto_44:

`NDPI_PROTOCOL_MODBUS`
=======================
Modbus is a serial communication protocol for connecting industrial electronic devices.

References: `Modbus Wikipedia article: <https://en.wikipedia.org/wiki/Modbus>`_


.. _Proto_45:

`NDPI_PROTOCOL_WHATSAPP_CALL`
=============================
WhatsApp Call protocol handles both audio and video calls within the WhatsApp messaging app.

References: `WhatsApp official site: <https://www.whatsapp.com/>`_


.. _Proto_46:

`NDPI_PROTOCOL_DATASAVER`
=========================
Data Saver (Lite Mode) is a Google Chrome feature designed to reduce mobile data usage by compressing web traffic.

References: `Google Chromium Blog: <https://blog.chromium.org/2019/04/data-saver-is-now-lite-mode.html>`_


.. _Proto_47:

`NDPI_PROTOCOL_XBOX`
====================
Xbox protocol covers network traffic associated with Microsoft’s Xbox gaming consoles.

References: `Xbox official site: <https://www.xbox.com/>`_


.. _Proto_48:

`NDPI_PROTOCOL_QQ`
==================
QQ is an instant messaging platform developed by Tencent popular in China.

References: `QQ official site: <https://im.qq.com/>`_


.. _Proto_49:

`NDPI_PROTOCOL_TIKTOK`
======================
TikTok is a video-sharing social networking service for short-format videos.

References: `TikTok official site: <https://www.tiktok.com/>`_


.. _Proto_50:

`NDPI_PROTOCOL_RTSP`
====================
RTSP (Real Time Streaming Protocol) controls streaming media servers.

References: `RFC2326: <https://datatracker.ietf.org/doc/html/rfc2326>`_


.. _Proto_51:

`NDPI_PROTOCOL_MAIL_IMAPS`
==========================
IMAPS (IMAP over SSL) is the secure version of the Internet Message Access Protocol for email retrieval.

References: `RFC3501: <https://datatracker.ietf.org/doc/html/rfc3501>`_ and `RFC8314 (IMAPS): <https://tools.ietf.org/html/rfc8314>`_


.. _Proto_52:

`NDPI_PROTOCOL_ICECAST`
=======================
Icecast is a streaming media project that supports audio/video streaming and broadcast.

References: `Icecast official site: <https://icecast.org/>`_


.. _Proto_53:

`NDPI_PROTOCOL_CPHA`
====================
Check Point High Availability (CPHA) Protocol provides firewall redundancy and failover.

References: `Check Point HA: <https://www.checkpoint.com/cyber-hub/network-security/what-is-firewall/high-availability-ha-firewall/>`_


.. _Proto_54:

`NDPI_PROTOCOL_IQIYI`
=====================
iQIYI is a Chinese online video platform with original and licensed movies, dramas, variety shows, and anime.

References: `iQIYI official site: <https://www.iqiyi.com/>`_


.. _Proto_59:

`NDPI_PROTOCOL_ADOBE_CONNECT`
=============================
Adobe Connect is a web conferencing platform for online meetings, webinars, and virtual classrooms.

References: `Adobe Connect official site: <https://www.adobe.com/products/adobeconnect.html>`_


.. _Proto_60:

`NDPI_PROTOCOL_MONGODB`
=======================
MongoDB is a popular NoSQL database system designed for scalability and flexibility.

References: `MongoDB official site: <https://www.mongodb.com/>`_


.. _Proto_61:

`NDPI_PROTOCOL_PLURALSIGHT`
===========================
Pluralsight is an online education platform offering tech skill development courses.

References: `Pluralsight official site: <https://www.pluralsight.com/>`_


.. _Proto_62:

`NDPI_PROTOCOL_YANDEX_CLOUD`
============================
Yandex.Cloud is a public cloud platform providing computing and storage services.

References: `Yandex.Cloud official site: <https://yandex.cloud/>`_


.. _Proto_63:

`NDPI_PROTOCOL_OCSP`
====================
OCSP (Online Certificate Status Protocol) checks the revocation status of digital certificates in real-time.

References: `RFC6960: <https://datatracker.ietf.org/doc/html/rfc6960/>`_


.. _Proto_64:

`NDPI_PROTOCOL_VXLAN`
=====================
VXLAN (Virtual Extensible LAN) extends layer 2 networks over layer 3 infrastructure.

References: `RFC7348: <https://datatracker.ietf.org/doc/html/rfc7348/>`_


.. _Proto_65:

`NDPI_PROTOCOL_IRC`
===================
IRC (Internet Relay Chat) is a text-based chat system for instant messaging.

References: `IRC Wikipedia article: <https://en.wikipedia.org/wiki/IRC>`_ and `IRC statistics: <https://netsplit.de/networks/top10.php>`_


.. _Proto_66:

`NDPI_PROTOCOL_MERAKI_CLOUD`
============================
Meraki Cloud is a cloud-based network management platform by Cisco Meraki.

References: `Meraki official site: <https://meraki.cisco.com/>`_


.. _Proto_67:

`NDPI_PROTOCOL_JABBER`
======================
Jabber is an open instant messaging protocol based on XMPP for real-time communication.

References: `XMPP standards: <https://xmpp.org/>`_


.. _Proto_68:

`NDPI_PROTOCOL_NATS`
====================
NATS is a high-performance messaging system for cloud-native applications and IoT.

References: `NATS official site: <https://nats.io/>`_


.. _Proto_69:

`NDPI_PROTOCOL_AMONG_US`
========================
Among Us is a multiplayer social deduction game developed by InnerSloth.

References: `InnerSloth official site: <https://www.innersloth.com/games/among-us/>`_


.. _Proto_70:

`NDPI_PROTOCOL_YAHOO`
=====================
Yahoo is a web services provider known for its email, news, and search engine products.

References: `Yahoo official site: <https://www.yahoo.com/>`_


.. _Proto_71:

`NDPI_PROTOCOL_DISNEYPLUS`
==========================
Disney+ is a streaming service offering movies and TV series from Disney franchises.

References: `Disney+ official site: <https://www.disneyplus.com/>`_


.. _Proto_72:

`NDPI_PROTOCOL_HART_IP`
=======================
Highway Addressable Remote Transducer over IP.

References: `HART-IP Protocol Specs: <https://library.fieldcommgroup.org/20085/TS20085>`_


.. _Proto_73:

`NDPI_PROTOCOL_IP_VRRP`
=======================
Virtual Router Redundancy Protocol (VRRP) provides automatic assignment of available IP routers to hosts.

References: `RFC5798: <https://datatracker.ietf.org/doc/html/rfc5798/>`_


.. _Proto_74:

`NDPI_PROTOCOL_STEAM`
=====================
Steam is a digital distribution platform developed by Valve Corporation for games.

References: `Steam official site: <https://store.steampowered.com/>`_


.. _Proto_75:

`NDPI_PROTOCOL_MELSEC`
======================
MELSEC is a proprietary industrial protocol used by Mitsubishi Electric PLCs for communication and control.

References: `MELSEC Communication Protocol Manual: <https://dl.mitsubishielectric.com/dl/fa/document/manual/plc/sh080008/sh080008ab.pdf>`_


.. _Proto_76:

`NDPI_PROTOCOL_WORLDOFWARCRAFT`
===============================
World of Warcraft (WoW) is a massively multiplayer online role-playing game (MMORPG).

References: `WoW official site: <https://worldofwarcraft.com/>`_


.. _Proto_77:

`NDPI_PROTOCOL_TELNET`
=======================
Telnet is a network protocol for interactive text communication.

References: `RFC854: <https://datatracker.ietf.org/doc/html/rfc854/>`_


.. _Proto_78:

`NDPI_PROTOCOL_STUN`
====================
STUN (Session Traversal Utilities for NAT) helps devices discover public IP addresses.

References: `RFC5389: <https://datatracker.ietf.org/doc/html/rfc5389/>`_


.. _Proto_79:

`NDPI_PROTOCOL_IPSEC`
======================
IPsec authenticates and encrypts IP packets for secure communication over IP networks.

References: `RFC4301: <https://datatracker.ietf.org/doc/html/rfc4301/>`_


.. _Proto_80:

`NDPI_PROTOCOL_IP_GRE`
======================
GRE (Generic Routing Encapsulation) tunnels packets to encapsulate various network protocols.

References: `RFC2784: <https://datatracker.ietf.org/doc/html/rfc2784/>`_


.. _Proto_81:

`NDPI_PROTOCOL_IP_ICMP`
=======================
ICMP (Internet Control Message Protocol) sends error messages and operational information.

References: `RFC792: <https://datatracker.ietf.org/doc/html/rfc792/>`_


.. _Proto_82:

`NDPI_PROTOCOL_IP_IGMP`
=======================
IGMP (Internet Group Management Protocol) manages membership of IP multicast groups.

References: `RFC2236: <https://datatracker.ietf.org/doc/html/rfc2236/>`_


.. _Proto_83:

`NDPI_PROTOCOL_IP_EGP`
======================
EGP (Exterior Gateway Protocol) is an obsolete protocol for exchanging routing info.

References: `RFC904: <https://datatracker.ietf.org/doc/html/rfc904/>`_


.. _Proto_84:

`NDPI_PROTOCOL_IP_SCTP`
=======================
SCTP (Stream Control Transmission Protocol) is a reliable transport layer protocol.

References: `RFC4960: <https://datatracker.ietf.org/doc/html/rfc4960/>`_


.. _Proto_85:

`NDPI_PROTOCOL_IP_OSPF`
=======================
OSPF (Open Shortest Path First) is a routing protocol for IP networks.

References: `RFC2328: <https://datatracker.ietf.org/doc/html/rfc2328/>`_


.. _Proto_86:

`NDPI_PROTOCOL_IP_IP_IN_IP`
===========================
IP-in-IP encapsulation allows an IP packet to be wrapped inside another IP packet.

References: `RFC2003: <https://datatracker.ietf.org/doc/html/rfc2003/>`_


.. _Proto_87:

`NDPI_PROTOCOL_RTP`
===================
RTP (Real-time Transport Protocol) provides end-to-end delivery services for real-time data.

References: `RFC3550: <https://datatracker.ietf.org/doc/html/rfc3550/>`_


.. _Proto_88:

`NDPI_PROTOCOL_RDP`
===================
RDP (Remote Desktop Protocol) is Microsoft's protocol for remote graphical desktop access.

References: `Remote Desktop Protocol Wikipedia article: <https://en.wikipedia.org/wiki/Remote_Desktop_Protocol>`_


.. _Proto_89:

`NDPI_PROTOCOL_VNC`
===================
VNC (Virtual Network Computing) allows remote control of other computers' desktops.

References: `VNC Wikipedia article: <https://en.wikipedia.org/wiki/VNC>`_


.. _Proto_90:

`NDPI_PROTOCOL_TUMBLR`
======================
Tumblr is a microblogging and social networking platform.

References: `Tumblr official site: <https://www.tumblr.com/>`_


.. _Proto_91:

`NDPI_PROTOCOL_TLS`
===================
TLS (Transport Layer Security) provides encryption for network communications.

References: `RFC8446: <https://datatracker.ietf.org/doc/html/rfc8446/>`_


.. _Proto_92:

`NDPI_PROTOCOL_SSH`
===================
SSH (Secure Shell) is a protocol for secure remote login and other network services.

References: `RFC4251: <https://datatracker.ietf.org/doc/html/rfc4251/>`_


.. _Proto_93:

`NDPI_PROTOCOL_USENET`
======================
Usenet is a distributed discussion system for newsgroups.

References: `Usenet Wikipedia article: <https://en.wikipedia.org/wiki/Usenet>`_


.. _Proto_94:

`NDPI_PROTOCOL_MGCP`
====================
MGCP (Media Gateway Control Protocol) controls media gateways on IP networks.

References: `RFC3435: <https://datatracker.ietf.org/doc/html/rfc3435/>`_


.. _Proto_95:

`NDPI_PROTOCOL_IAX`
===================
IAX (Inter-Asterisk eXchange protocol) is used for VoIP sessions, originally for Asterisk PBX.

References: `RFC5456: <https://datatracker.ietf.org/doc/rfc5456/>`_


.. _Proto_96:

`NDPI_PROTOCOL_TFTP`
======================
TFTP (Trivial File Transfer Protocol) is a simple file transfer protocol.

References: `RFC1350: <https://datatracker.ietf.org/doc/html/rfc1350>`_, `RFC2347: <https://datatracker.ietf.org/doc/html/rfc2347>`_, `RFC2349: <https://datatracker.ietf.org/doc/html/rfc2349>`_


.. _Proto_97:

`NDPI_PROTOCOL_AFP`
====================
AFP (Apple Filing Protocol) is a network protocol for file services on macOS.

References: `AFP Wikipedia article: <https://en.wikipedia.org/wiki/Apple_Filing_Protocol>`_


.. _Proto_98:

`NDPI_PROTOCOL_YANDEX_METRIKA`
================================
Yandex Metrika is a web analytics service by Yandex to track website traffic.

References: `Yandex Metrika official site: <https://metrika.yandex.com/>`_


.. _Proto_99:

`NDPI_PROTOCOL_YANDEX_DIRECT`
==============================
Yandex.Direct is an online advertising platform for contextual ads.

References: `Yandex.Direct official site: <https://ads.yandex.com/direct_eng/>`_


.. _Proto_100:

`NDPI_PROTOCOL_SIP`
====================
SIP (Session Initiation Protocol) is used for real-time communication session control.

References: `RFC3261: <https://datatracker.ietf.org/doc/html/rfc3261/>`_


.. _Proto_101:

`NDPI_PROTOCOL_TRUPHONE`
=========================
Truphone is a global mobile network provider using eSIM and VoIP.

References: `Truphone official site: <https://www.truphone.com/>`_


.. _Proto_102:

`NDPI_PROTOCOL_IP_ICMPV6`
==========================
ICMPv6 is integral to IPv6 for diagnostics and error reporting.

References: `RFC4443: <https://datatracker.ietf.org/doc/html/rfc4443>`_


.. _Proto_103:

`NDPI_PROTOCOL_DHCPV6`
=======================
DHCPv6 dynamically assigns IPv6 addresses and settings.

References: `RFC8415: <https://datatracker.ietf.org/doc/html/rfc8415>`_


.. _Proto_104:

`NDPI_PROTOCOL_ARMAGETRON`
===========================
Armagetron Advanced is a 3D multiplayer game inspired by Tron light cycles.

References: `Armagetron official site: <https://armagetronad.org/>`_


.. _Proto_105:

`NDPI_PROTOCOL_CROSSFIRE`
=========================
Crossfire is an online FPS game with team combat and various modes.

References: `Crossfire official site: <https://crossfire.z8games.com/>`_


.. _Proto_106:

`NDPI_PROTOCOL_DOFUS`
=======================
Dofus is a tactical MMORPG with turn-based combat.

References: `Dofus official site: <https://www.dofus.com/>`_


.. _Proto_109:

`NDPI_PROTOCOL_GUILDWARS2`
==========================
Guild Wars is an online RPG known for dynamic events and PvP.

References: `Guild Wars 2 official site: <https://www.guildwars2.com/>`_


.. _Proto_110:

`NDPI_PROTOCOL_AMAZON_ALEXA`
============================
Amazon Alexa voice service protocol for smart devices.

References: `Amazon Alexa developer site: <https://developer.amazon.com/en-US/alexa/>`_


.. _Proto_111:

`NDPI_PROTOCOL_KERBEROS`
=========================
Kerberos is a protocol for secure network authentication.

References: `RFC4120: <https://datatracker.ietf.org/doc/html/rfc4120/>`_


.. _Proto_112:

`NDPI_PROTOCOL_LDAP`
=====================
LDAP is a protocol for accessing directory services.

References: `RFC4510: <https://datatracker.ietf.org/doc/html/rfc4510>`_


.. _Proto_113:

`NDPI_PROTOCOL_NEXON`
=======================
Nexon is a South Korean video game developer and publisher.

References: `Nexon official site: <https://www.nexon.com>`_


.. _Proto_116:

`NDPI_PROTOCOL_IP_AH`
=====================
An Authentication Header (AH) is a security protocol in IPSec that ensures the integrity of packet headers and data, provides user authentication, and offers optional replay protection and access protection. It does not encrypt any part of the packets.

References: `RFC4302: <https://datatracker.ietf.org/doc/html/rfc4302>`_


.. _Proto_117:

`NDPI_PROTOCOL_IP_ESP`
======================
Encapsulating Security Payload (ESP) is a crucial protocol within the IPsec framework, designed to protect the confidentiality, integrity, and authentication of IP packets. It achieves this by encrypting the payload (the data being transmitted) and potentially authenticating the sender and validating the data's integrityencrypt any part of the packets.

References: `RFC4303: <https://datatracker.ietf.org/doc/html/rfc4303>`_


.. _Proto_125:

`NDPI_PROTOCOL_MOZILLA`
========================
Mozilla-related traffic, especially Firefox browser.

References: `Mozilla official site: <https://www.mozilla.org>`_


.. _Proto_126:

`NDPI_PROTOCOL_GOOGLE`
======================
Google's internet services and products traffic.

References: `Google official site: <https://www.google.com/>`_


.. _Proto_127:

`NDPI_PROTOCOL_MS_RPCH`
=======================
Microsoft RPC protocol over HTTP.

References: `Microsoft RPCH specs: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpch/c0f4c9c5-1a61-4d10-b8e2-005378d1d212>`_


.. _Proto_128:

`NDPI_PROTOCOL_NETFLOW`
=======================
NetFlow is a network protocol developed by Cisco for collecting IP traffic information and monitoring network traffic flow.

References: `RFC3954: <https://tools.ietf.org/html/rfc3954>`_


.. _Proto_129:

`NDPI_PROTOCOL_SFLOW`
=====================
sFlow is a packet sampling technology for monitoring traffic in data networks in real time.

References: `sFlow Wikipedia article: <https://en.wikipedia.org/wiki/SFlow>`_


.. _Proto_130:

`NDPI_PROTOCOL_HTTP_CONNECT`
============================
HTTP CONNECT method is used to establish a tunnel to the server, typically for SSL traffic through proxies.

References: `RFC7231: <https://tools.ietf.org/html/rfc7231#section-4.3.6>`_


.. _Proto_132:

`NDPI_PROTOCOL_CITRIX`
======================
Citrix provides remote access and virtualization solutions for secure delivery of applications and desktops.

References: `Citrix official site: <https://www.citrix.com/>`_


.. _Proto_133:

`NDPI_PROTOCOL_NETFLIX`
=======================
Netflix is a leading streaming entertainment service delivering movies, TV shows, and original content.

References: `Netflix official site: <https://www.netflix.com/>`_


.. _Proto_134:

`NDPI_PROTOCOL_LASTFM`
=======================
Last.fm is a music recommendation and streaming service that provides personalized music charts and discovery.

References: `Last.fm official site: <https://www.last.fm/>`_


.. _Proto_135:

`NDPI_PROTOCOL_WAZE`
====================
Waze is a GPS navigation app providing real-time traffic and road info.

References: `Waze official site: <https://www.waze.com/>`_


.. _Proto_137:

`NDPI_PROTOCOL_HULU`
====================
Hulu is a streaming platform offering live and on-demand TV and movies.

References: `Hulu official site: <https://www.hulu.com/>`_


.. _Proto_138:

`NDPI_PROTOCOL_CHECKMK`
=======================
Checkmk is an IT monitoring system for servers, apps, networks, and cloud.

References: `Checkmk official site: <https://checkmk.com/>`_


.. _Proto_139:

`NDPI_PROTOCOL_AJP`
===================
Apache JServ Protocol (AJP) proxies web server requests to application servers.

References: `AJP Protocol Specs: <https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html>`_


.. _Proto_140:

`NDPI_PROTOCOL_APPLE`
=====================
Apple protocol includes various services related to Apple devices and ecosystem.

References: `Apple official site: <https://www.apple.com/>`_


.. _Proto_141:

`NDPI_PROTOCOL_WEBEX`
======================
Webex is a video conferencing and online meeting application by Cisco.

References: `Webex official site: <https://www.webex.com/>`_


.. _Proto_142:

`NDPI_PROTOCOL_WHATSAPP`
=========================
WhatsApp is a messaging app by Meta, offering encrypted messaging and calls.

References: `WhatsApp official site: <https://www.whatsapp.com/>`_


.. _Proto_143:

`NDPI_PROTOCOL_APPLE_ICLOUD`
=============================
iCloud is Apple’s cloud storage and computing service.

References: `iCloud official site: <https://www.icloud.com/>`_


.. _Proto_144:

`NDPI_PROTOCOL_VIBER`
======================
Viber is a cross-platform messaging and VoIP app.

References: `Viber official site: <https://www.viber.com/>`_


.. _Proto_145:

`NDPI_PROTOCOL_APPLE_ITUNES`
=============================
Apple iTunes is a media player and content store.

References: `iTunes official site: <https://www.apple.com/itunes/>`_


.. _Proto_146:

`NDPI_PROTOCOL_RADIUS`
=======================
RADIUS protocol provides centralized Authentication, Authorization, and Accounting.

References: `RFC2865: <https://tools.ietf.org/html/rfc2865>`_


.. _Proto_148:

`NDPI_PROTOCOL_TEAMVIEWER`
============================
TeamViewer is remote access software for desktop sharing and file transfer.

References: `TeamViewer official site: <https://www.teamviewer.com/>`_


.. _Proto_149:

`NDPI_PROTOCOL_EGD`
=========================
Ethernet Global Data (EGD) protocol for real-time data exchange in industrial automation.

References: `EGD Wikipedia article: <https://en.wikipedia.org/wiki/Ethernet_Global_Data_Protocol>`_

Notes:

- This dissector only works for data packets, not configuration commands.
- IPv6 is not supported.


.. _Proto_150:

`NDPI_PROTOCOL_HCL_NOTES`
===========================
HCL Notes (formerly Lotus Notes) is a collaborative client-server application.

References: `HCL Notes official site: <https://www.hcl-software.com/notes>`_


.. _Proto_151:

`NDPI_PROTOCOL_SAP`
=====================
Session Announcement Protocol (SAP) announces multicast session info.

References: `RFC2974: <https://datatracker.ietf.org/doc/html/rfc2974>`_


.. _Proto_152:

`NDPI_PROTOCOL_GTP`
=====================
GPRS Tunneling Protocol (GTP) carries mobile data within GSM and UMTS.

References: `GTP Wikipedia article: <https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol>`_


.. _Proto_153:

`NDPI_PROTOCOL_WSD`
=====================
Web Services Dynamic Discovery (WS-Discovery) locates services on local networks.

References: `WS-Discovery Wikipedia article: <https://en.wikipedia.org/wiki/WS-Discovery>`_


.. _Proto_154:

`NDPI_PROTOCOL_LLMNR`
======================
Link-Local Multicast Name Resolution (LLMNR) resolves names on local links.

References: `RFC4795: <https://datatracker.ietf.org/doc/html/rfc4795>`_


.. _Proto_155:

`NDPI_PROTOCOL_TOCA_BOCA`
==========================
Toca Boca produces creative mobile games for children.

References: `Toca Boca official site: <https://tocaboca.com/>`_


.. _Proto_156:

`NDPI_PROTOCOL_SPOTIFY`
========================
Spotify is a music streaming service offering millions of tracks and podcasts.

References: `Spotify official site: <https://www.spotify.com/>`_


.. _Proto_157:

`NDPI_PROTOCOL_FACEBOOK_MESSENGER`
===================================
Facebook Messenger is an instant messaging service by Meta.

References: `Messenger official site: <https://www.messenger.com/>`_


.. _Proto_158:

`NDPI_PROTOCOL_H323`
=====================
H.323 is a standard for real-time voice, video, and data communications.

References: `ITU-T H.323: <https://www.itu.int/rec/T-REC-H.323>`_


.. _Proto_159:

`NDPI_PROTOCOL_OPENVPN`
========================
OpenVPN is an open-source VPN protocol for secure connections.

References: `OpenVPN official site: <https://openvpn.net/>`_


.. _Proto_160:

`NDPI_PROTOCOL_NOE`
====================
NOE is a VoIP protocol for Alcatel-Lucent compatible telephone systems.

References: `Teldat Manual: <https://support.teldat.com/images/content/docs/teldat_dm777_NOE_Protocol.pdf>`_


.. _Proto_161:

`NDPI_PROTOCOL_CISCOVPN`
=========================
Cisco VPN protocols secure virtual private network connections.

References: `Cisco VPN site: <https://www.cisco.com/site/us/en/products/security/vpn/index.html>`_


.. _Proto_162:

`NDPI_PROTOCOL_TEAMSPEAK`
==========================
TeamSpeak is a voice-over-IP app for gamer communication.

References: `TeamSpeak official site: <https://www.teamspeak.com/>`_


.. _Proto_163:

`NDPI_PROTOCOL_TOR`
====================
Tor enables anonymous communication via onion routing.

References: `Tor Project site: <https://www.torproject.org/>`_


.. _Proto_164:

`NDPI_PROTOCOL_SKINNY`
=======================
Skinny Client Control Protocol (SCCP) is a Cisco VoIP signaling protocol.

References: `SCCP Wikipedia article: <https://en.wikipedia.org/wiki/Skinny_Client_Control_Protocol>`_


.. _Proto_165:

`NDPI_PROTOCOL_RTCP`
=====================
RTCP (Real-time Transport Control Protocol) works alongside RTP.

References: `RFC3550 Section 6: <https://datatracker.ietf.org/doc/html/rfc3550#section-6>`_


.. _Proto_166:

`NDPI_PROTOCOL_RSYNC`
======================
Rsync is a fast incremental file transfer utility.

References: `Rsync homepage: <https://rsync.samba.org/>`_


.. _Proto_167:

`NDPI_PROTOCOL_ORACLE`
=======================
Oracle database communication protocol.

References: `Oracle Net Services docs: <https://docs.oracle.com/en/database/oracle/oracle-database/19/netrf/index.html>`_


.. _Proto_168:

`NDPI_PROTOCOL_CORBA`
======================
CORBA enables software components to communicate over a network.

References: `OMG CORBA: <https://www.omg.org/spec/CORBA/About-CORBA/>`_


.. _Proto_169:

`NDPI_PROTOCOL_CANONICAL`
===========================
Canonical Ltd., developer of Ubuntu Linux and related services.

References: `Canonical official site: <https://canonical.com/>`_


.. _Proto_170:

`NDPI_PROTOCOL_WHOIS_DAS`
===========================
WHOIS DAS queries databases storing Internet resource assignments.

References: `WHOIS Wikipedia article: <https://en.wikipedia.org/wiki/WHOIS>`_


.. _Proto_171:

`NDPI_PROTOCOL_SD_RTN`
========================
Agora SD-RTN is a global, private, secure real-time network for low-latency streaming.

References: `Agora platform info: <https://www.agora.io/en/the-agora-platform-advantage/>`_


.. _Proto_172:

`NDPI_PROTOCOL_SOCKS`
======================
SOCKS routes network packets through proxy servers.

References: `RFC1928: <https://tools.ietf.org/html/rfc1928>`_


.. _Proto_173:

`NDPI_PROTOCOL_NINTENDO`
=========================
Nintendo network communication protocols for consoles and services.

References: `Nintendo official site: <https://www.nintendo.com/>`_


.. _Proto_174:

`NDPI_PROTOCOL_RTMP`
=====================
RTMP (Real-Time Messaging Protocol) streams audio, video, and data.

References: `RTMP Wikipedia article: <https://en.wikipedia.org/wiki/Real-Time_Messaging_Protocol>`_


.. _Proto_175:

`NDPI_PROTOCOL_FTP_DATA`
=========================
FTP Data Protocol transfers data separately from control connections.

References: `FTP Wikipedia article: <https://en.wikipedia.org/wiki/File_Transfer_Protocol>`_


.. _Proto_176:

`NDPI_PROTOCOL_WIKIPEDIA`
==========================
Wikipedia is a free, collaborative, multilingual online encyclopedia.

References: `Wikipedia official site: <https://www.wikipedia.org>`_


.. _Proto_177:

`NDPI_PROTOCOL_ZMQ`
====================
ZeroMQ (ZMQ) is a high-performance asynchronous messaging library.

References: `ZeroMQ official site: <https://zeromq.org/>`_


.. _Proto_178:

`NDPI_PROTOCOL_AMAZON`
=======================
Amazon network traffic including retail, AWS, and content delivery.

References: `Amazon official site: <https://www.amazon.com>`_


.. _Proto_179:

`NDPI_PROTOCOL_EBAY`
=====================
eBay is an online marketplace for quality goods and services.

References: `eBay official site: <https://www.ebay.com>`_


.. _Proto_180:

`NDPI_PROTOCOL_CNN`
====================
CNN is an American news television channel providing 24-hour news coverage.

References: `CNN official site: <https://edition.cnn.com>`_


.. _Proto_181:

`NDPI_PROTOCOL_MEGACO`
======================
Megaco (H.248) protocol for controlling media gateways in VoIP.

References: `ITU-T H.248: <https://www.itu.int/rec/T-REC-H.248.1>`_


.. _Proto_182:

`NDPI_PROTOCOL_RESP`
=======================
Redis Serialization Protocol.

References: `Redis Protocol Specs: <https://redis.io/docs/reference/protocol-spec/>`_


.. _Proto_183:

`NDPI_PROTOCOL_PINTEREST`
==========================
Pinterest is a social media platform for sharing images and ideas.

References: `Pinterest official site: <https://www.pinterest.com/>`_


.. _Proto_184:

`NDPI_PROTOCOL_OSPF`
=======================
OSPF (Open Shortest Path First) is a routing protocol for IP networks.

References: `RFC2328: <https://datatracker.ietf.org/doc/html/rfc2328/>`_


.. _Proto_185:

`NDPI_PROTOCOL_TELEGRAM`
=========================
Telegram is a cloud-based instant messaging app focusing on speed and security.

References: `Telegram official site: <https://telegram.org/>`_


.. _Proto_186:

`NDPI_PROTOCOL_COD_MOBILE`
===========================
Call of Duty: Mobile is a popular shooter game for iOS and Android.

References: `COD Mobile official site: <https://www.callofduty.com/mobile/>`_


.. _Proto_187:

`NDPI_PROTOCOL_PANDORA`
========================
Pandora is an Internet radio and streaming music service.

References: `Pandora official site: <https://www.pandora.com/>`_


.. _Proto_188:

`NDPI_PROTOCOL_QUIC`
=====================
QUIC is a transport layer protocol by Google improving web app performance.

References: `RFC9000: <https://datatracker.ietf.org/doc/html/rfc9000>`_


.. _Proto_189:

`NDPI_PROTOCOL_ZOOM`
=====================
Zoom is a popular video conferencing platform.

References: `Zoom official site: <https://zoom.us/>`_


.. _Proto_190:

`NDPI_PROTOCOL_EAQ`
====================
EAQ is a Brazilian organization measuring broadband quality.

References: `EAQ official site: <http://www.brasilbandalarga.com.br>`_


.. _Proto_191:

`NDPI_PROTOCOL_OOKLA`
======================
Ookla operates Speedtest.net for network performance testing.

References: `Speedtest.net: <https://www.speedtest.net/>`_


.. _Proto_192:

`NDPI_PROTOCOL_AMQP`
=====================
AMQP is an open standard application layer protocol for messaging middleware.

References: `AMQP official site: <https://www.amqp.org/>`_


.. _Proto_193:

`NDPI_PROTOCOL_KAKAOTALK`
==========================
KakaoTalk is a South Korean mobile messaging app (text only).

References: `Kakao official site: <https://www.kakaocorp.com/page/service/service/KakaoTalk?lang=ENG&tab=all>`_


.. _Proto_194:

`NDPI_PROTOCOL_KAKAOTALK_VOICE`
================================
KakaoTalk Voice adds voice call functionality within KakaoTalk.

References: `Kakao official site: <https://www.kakaocorp.com/page/service/service/KakaoTalk?lang=ENG&tab=all>`_


.. _Proto_195:

`NDPI_PROTOCOL_TWITCH`
=======================
Twitch is a live streaming platform for gaming and esports.

References: `Twitch official site: <https://www.twitch.tv/>`_


.. _Proto_196:

`NDPI_PROTOCOL_DOH_DOT`
========================
DNS over HTTPS (DoH), DNS over TLS (DoT), and DNS over QUIC (DoQ) encrypt DNS queries.

References: `DoH RFC8484: <https://datatracker.ietf.org/doc/html/rfc8484>`_, `DoT RFC7858: <https://datatracker.ietf.org/doc/html/rfc7858>`_


.. _Proto_197:

`NDPI_PROTOCOL_WECHAT`
=======================
WeChat is a Chinese messaging, social media, and payment app.

References: `WeChat official site: <https://www.wechat.com/>`_


.. _Proto_198:

`NDPI_PROTOCOL_MPEGTS`
=======================
MPEG Transport Stream (TS) is a standard for transmission/storage of audio, video, data.

References: `MPEG-TS Wikipedia article: <https://en.wikipedia.org/wiki/MPEG_transport_stream>`_


.. _Proto_199:

`NDPI_PROTOCOL_SNAPCHAT`
=========================
Snapchat is a multimedia messaging app known for ephemeral messages.

References: `Snapchat official site: <https://www.snapchat.com/>`_


.. _Proto_200:

`NDPI_PROTOCOL_SINA`
=====================
Sina is a Chinese company operating web services including Sina Weibo.

References: `Sina official site: <http://www.sina.com.cn/>`_


.. _Proto_201:

`NDPI_PROTOCOL_GOOGLE_MEET`
===========================
Google Meet is Google’s video conferencing service.

References: `Google Meet official site: <https://meet.google.com/>`_


.. _Proto_202:

`NDPI_PROTOCOL_IFLIX`
=====================
iflix is a video on demand service for emerging markets.

References: `iflix official site: <https://www.iflix.com>`_


.. _Proto_203:

`NDPI_PROTOCOL_GITHUB`
=======================
GitHub is a platform for version control and collaborative development.

References: `GitHub official site: <https://github.com>`_


.. _Proto_204:

`NDPI_PROTOCOL_BJNP`
=====================
BJNP is a proprietary USB-over-IP network printing discovery protocol by Canon.

References: Canon proprietary, no public specs available.


.. _Proto_205:

`NDPI_PROTOCOL_REDDIT`
=======================
Reddit is a social news and discussion website.

References: `Reddit official site: <https://www.reddit.com>`_


.. _Proto_206:

`NDPI_PROTOCOL_WIREGUARD`
===========================
WireGuard is a modern VPN protocol noted for simplicity and speed.

References: `WireGuard official site: <https://www.wireguard.com>`_


.. _Proto_207:

`NDPI_PROTOCOL_SMPP`
=====================
SMPP is a protocol for exchanging SMS messages.

References: `SMPP official site: <https://www.smpp.org/>`_


.. _Proto_208:

`NDPI_PROTOCOL_DNSCRYPT`
=========================
DNSCrypt authenticates and encrypts DNS traffic.

References: `DNSCrypt official site: <https://dnscrypt.info>`_


.. _Proto_209:

`NDPI_PROTOCOL_TINC`
=====================
Tinc is an open-source VPN daemon creating secure private networks.

References: `Tinc official site: <https://www.tinc-vpn.org>`_


.. _Proto_210:

`NDPI_PROTOCOL_DEEZER`
=======================
Deezer is a music streaming service.

References: `Deezer official site: <https://www.deezer.com>`_


.. _Proto_211:

`NDPI_PROTOCOL_INSTAGRAM`
==========================
Instagram is a social app for photo and video sharing.

References: `Instagram official site: <https://www.instagram.com>`_


.. _Proto_212:

`NDPI_PROTOCOL_MICROSOFT`
=========================
Microsoft protocol includes various proprietary communications.

References: `Microsoft official site: <https://www.microsoft.com>`_


.. _Proto_213:

`NDPI_PROTOCOL_BLIZZARD`
========================
Blizzard Entertainment is a game developer known for WoW, Diablo, StarCraft.

References: `Blizzard official site: <https://www.blizzard.com>`_


.. _Proto_235:

`NDPI_PROTOCOL_VALVE_SDR`
===========================
Steam Datagram Relay (SDR) is Valve's virtual private gaming network.

References: `Steamworks partner doc: <https://partner.steamgames.com/doc/features/multiplayer/steamdatagramrelay>`_


.. _Proto_236:

`NDPI_PROTOCOL_LISP`
======================
LISP separates IP addresses into Endpoint IDs and Routing Locators.

References: `RFC6830: <https://www.rfc-editor.org/rfc/rfc6830>`_


.. _Proto_237:

`NDPI_PROTOCOL_DIAMETER`
=========================
Diameter is an AAA network protocol, successor to RADIUS.

References: `RFC6733: <https://datatracker.ietf.org/doc/html/rfc6733>`_


.. _Proto_238:

`NDPI_PROTOCOL_APPLE_PUSH`
============================
Apple Push Notification Service (APNs) delivers notifications to Apple devices.

References: `Apple Developer APNs: <https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server>`_


.. _Proto_239:

`NDPI_PROTOCOL_GOOGLE_SERVICES`
================================
Google Services cover various APIs and endpoints used by Google.

References: No single official site; includes googleapis.com, googletagmanager.com.


.. _Proto_240:

`NDPI_PROTOCOL_AMAZON_VIDEO`
=============================
Amazon Video is Amazon's video streaming service.

References: `Amazon Video site: <https://www.amazon.com/gp/video/storefront>`_


.. _Proto_241:

`NDPI_PROTOCOL_GOOGLE_DOCS`
============================
Google Docs allows collaborative online document editing.

References: `Google Docs official site: <https://docs.google.com>`_


.. _Proto_242:

`NDPI_PROTOCOL_WHATSAPP_FILES`
================================
WhatsApp media files such as videos, pictures, and voice messages.

References: `WhatsApp FAQ: <https://faq.whatsapp.com/>`_


.. _Proto_243:

`NDPI_PROTOCOL_TARGUS_GETDATA`
================================
Targus GetData is a proprietary protocol for Targus device data transfer.

References: Proprietary, no public documentation.


.. _Proto_244:

`NDPI_PROTOCOL_DNP3`
=====================
DNP3 is a communication protocol for process automation systems.

References: `DNP3 Wikipedia article: <https://en.wikipedia.org/wiki/DNP3>`_


.. _Proto_245:

`NDPI_PROTOCOL_IEC60870`
=========================
IEC 60870-5-104 network protocol used in power system telecontrol and supervision.

References: `IEC 60870 Wikipedia: <https://en.wikipedia.org/wiki/IEC_60870-5>`_


.. _Proto_246:

`NDPI_PROTOCOL_BLOOMBERG`
==========================
Bloomberg services traffic identified by domains and ASN registrations.

References: `Bloomberg official site: <https://www.bloomberg.com/>`_


.. _Proto_247:

`NDPI_PROTOCOL_CAPWAP`
========================
CAPWAP protocol manages wireless access points centrally.

References: `RFC5415: <https://datatracker.ietf.org/doc/html/rfc5415>`_


.. _Proto_248:

`NDPI_PROTOCOL_ZABBIX`
========================
Zabbix protocol supports agent-server communication for monitoring.

References: `Zabbix Documentation: <https://www.zabbix.com/documentation>`_


.. _Proto_249:

`NDPI_PROTOCOL_S7COMM`
=======================
S7Comm is Siemens PLC communication protocol.

References: `Wireshark S7comm wiki: <https://wiki.wireshark.org/S7comm>`_


.. _Proto_250:

`NDPI_PROTOCOL_MSTEAMS`
========================
Microsoft Teams collaboration app protocol.

References: `Microsoft Teams official site: <https://www.microsoft.com/it-it/microsoft-teams/group-chat-software>`_

Notes:

- This ID is also used for Skype traffic.


.. _Proto_251:

`NDPI_PROTOCOL_WEBSOCKET`
===========================
WebSocket provides full-duplex communication channels over TCP.

References: `RFC6455: <https://datatracker.ietf.org/doc/html/rfc6455>`_


.. _Proto_252:

`NDPI_PROTOCOL_ANYDESK`
========================
AnyDesk is a platform-independent remote desktop app.

References: `AnyDesk official site: <https://anydesk.com/>`_


.. _Proto_253:

`NDPI_PROTOCOL_SOAP`
=====================
SOAP is a protocol for exchanging structured info in web services using XML.

References: `W3C SOAP spec: <https://www.w3.org/TR/soap/>`_


.. _Proto_254:

`NDPI_PROTOCOL_APPLE_SIRI`
===========================
Apple Siri is a voice assistant integrated into Apple devices.

References: `Apple Siri official: <https://www.apple.com/siri/>`_


.. _Proto_255:

`NDPI_PROTOCOL_SNAPCHAT_CALL`
===============================
Snapchat Call provides voice and video communication between users.

References: `Snapchat official site: <https://www.snapchat.com/>`_


.. _Proto_256:

`NDPI_PROTOCOL_HPVIRTGRP`
==========================
HP Virtual Group is HP's proprietary virtualization protocol.

References: Proprietary, no public documentation.


.. _Proto_257:

`NDPI_PROTOCOL_GENSHIN_IMPACT`
================================
Genshin Impact is an action RPG game with live data exchanges.

References: `Genshin Impact official site: <https://genshin.hoyoverse.com/en>`_


.. _Proto_258:

`NDPI_PROTOCOL_ACTIVISION`
============================
Activision network traffic, including Call of Duty games.

References: `Activision official site: <https://www.activision.com/>`_


.. _Proto_259:

`NDPI_PROTOCOL_FORTICLIENT`
=============================
FortiClient security suite with VPN and endpoint protection.

References: `FortiClient official site: <https://www.fortinet.com/products/endpoint-security/forticlient>`_


.. _Proto_260:

`NDPI_PROTOCOL_Z3950`
=======================
Z39.50 protocol for searching and retrieving info from remote databases, often library systems.

References: `Library of Congress Z39.50: <https://www.loc.gov/z3950/>`_


.. _Proto_261:

`NDPI_PROTOCOL_LIKEE`
======================
Likee is a short-video creation and sharing platform.

References: `Likee official site: <https://likee.video>`_


.. _Proto_262:

`NDPI_PROTOCOL_GITLAB`
========================
GitLab is a DevOps platform with Git repository management and CI/CD.

References: `GitLab official site: <https://gitlab.com>`_


.. _Proto_263:

`NDPI_PROTOCOL_AVAST_SECUREDNS`
=================================
Avast Secure DNS provides safer browsing by blocking unsafe websites.

References: `Avast Secure DNS site: <https://www.avast.com/secure-dns>`_


.. _Proto_264:

`NDPI_PROTOCOL_CASSANDRA`
==========================
Apache Cassandra is a distributed NoSQL database system for big data.

References: `Cassandra official site: <https://cassandra.apache.org>`_


.. _Proto_265:

`NDPI_PROTOCOL_AMAZON_AWS`
===========================
Amazon Web Services (AWS) cloud computing platform.

References: `AWS official site: <https://aws.amazon.com>`_


.. _Proto_266:

`NDPI_PROTOCOL_SALESFORCE`
===========================
Salesforce is a cloud-based CRM platform.

References: `Salesforce official site: <https://www.salesforce.com>`_


.. _Proto_267:

`NDPI_PROTOCOL_VIMEO`
======================
Vimeo is a video hosting and sharing platform.

References: `Vimeo official site: <https://vimeo.com>`_


.. _Proto_268:

`NDPI_PROTOCOL_FACEBOOK_VOIP`
==============================
Facebook’s voice over IP communications within Messenger.

References: `Facebook Messenger: <https://www.messenger.com>`_


.. _Proto_269:

`NDPI_PROTOCOL_SIGNAL_VOIP`
=============================
Signal’s encrypted voice calling feature.

References: `Signal official site: <https://signal.org>`_


.. _Proto_270:

`NDPI_PROTOCOL_FUZE`
=====================
Fuze is a unified communications platform.

References: `Fuze official site: <https://www.fuze.com>`_


.. _Proto_271:

`NDPI_PROTOCOL_GTP_U`
========================
GTP-U carries user data within mobile networks.

References: `3GPP TS 29.060: <https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1595>`_


.. _Proto_272:

`NDPI_PROTOCOL_GTP_C`
=======================
GTP-C controls tunnel establishment in mobile networks.

References: `3GPP TS 29.060: <https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1595>`_


.. _Proto_273:

`NDPI_PROTOCOL_GTP_PRIME`
===========================
GTP Prime is a signaling protocol used in LTE for billing and charging.

References: `3GPP TS 32.295: <https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1912>`_


.. _Proto_274:

`NDPI_PROTOCOL_ALIBABA`
========================
Alibaba is a major Chinese conglomerate specializing in e-commerce and technology.

References: `Alibaba official site: <https://www.alibabagroup.com>`_


.. _Proto_275:

`NDPI_PROTOCOL_CRASHLYSTICS`
==============================
Crashlytics is a crash reporting tool by Google Firebase.

References: `Crashlytics on Firebase: <https://firebase.google.com/products/crashlytics>`_


.. _Proto_276:

`NDPI_PROTOCOL_MICROSOFT_AZURE`
================================
Microsoft Azure cloud computing platform.

References: `Azure official site: <https://azure.microsoft.com>`_


.. _Proto_277:

`NDPI_PROTOCOL_ICLOUD_PRIVATE_RELAY`
=====================================
iCloud Private Relay increases privacy by routing traffic through multiple relays.

References: `Apple iCloud Private Relay: <https://support.apple.com/en-us/102602>`_


.. _Proto_278:

`NDPI_PROTOCOL_ETHERNET_IP`
=============================
Ethernet/IP adapts the Common Industrial Protocol to Ethernet.

References: `ODVA Ethernet/IP: <https://www.odva.org/technology-standards/key-technologies/ethernet-ip/>`_


.. _Proto_279:

`NDPI_PROTOCOL_BADOO`
======================
Badoo is a social networking and dating service.

References: `Badoo official site: <https://badoo.com>`_


.. _Proto_280:

`NDPI_PROTOCOL_ACCUWEATHER`
=============================
AccuWeather provides real-time weather forecasts and alerts.

References: `AccuWeather official site: <https://www.accuweather.com>`_


.. _Proto_281:

`NDPI_PROTOCOL_GOOGLE_CLASSROOM`
=================================
Google Classroom simplifies school assignment management.

References: `Google Classroom: <https://classroom.google.com>`_


.. _Proto_282:

`NDPI_PROTOCOL_HSRP`
=====================
HSRP provides IP network failover and redundancy.

References: `Cisco HSRP guide: <https://www.cisco.com/c/en/us/support/docs/ip/hot-standby-router-protocol-hsrp/9234-hsrpguidetoc.html>`_


.. _Proto_284:

`NDPI_PROTOCOL_GOOGLE_CLOUD`
==============================
Google Cloud provides cloud computing services.

References: `Google Cloud official site: <https://cloud.google.com>`_


.. _Proto_285:

`NDPI_PROTOCOL_TENCENT`
=========================
Tencent network services and applications.

References: `Tencent official site: <https://www.tencent.com/en-us>`_


.. _Proto_286:

`NDPI_PROTOCOL_RAKNET`
========================
RakNet is a C++ game networking engine.

References: `RakNet on GitHub: <https://github.com/OculusVR/RakNet>`_


.. _Proto_287:

`NDPI_PROTOCOL_XIAOMI`
========================
Xiaomi communication protocols for devices and IoT.

References: `Xiaomi official site: <https://www.mi.com/global/>`_


.. _Proto_289:

`NDPI_PROTOCOL_CACHEFLY`
=========================
CacheFly is a content delivery network focused on video streaming.

References: `CacheFly official site: <https://www.cachefly.com>`_


.. _Proto_290:

`NDPI_PROTOCOL_SOFTETHER`
==========================
SoftEther VPN supports multiple protocols including SSL-VPN and L2TP.

References: `SoftEther official site: <https://www.softether.org>`_


.. _Proto_291:

`NDPI_PROTOCOL_MPEGDASH`
=========================
MPEG-DASH enables adaptive bitrate streaming over the Internet.

References: `MPEG-DASH specs: <https://www.mpeg.org/standards/MPEG-DASH/>`_


.. _Proto_292:

`NDPI_PROTOCOL_DAZN`
====================
DAZN is a sports subscription video streaming service.

References: `DAZN official site: <https://www.dazn.com>`_


.. _Proto_293:

`NDPI_PROTOCOL_GOTO`
=====================
GoTo includes services like GoToMeeting for online collaboration.

References: `GoTo official site: <https://www.goto.com>`_


.. _Proto_294:

`NDPI_PROTOCOL_RSH`
===================
Remote Shell (rsh) executes shell commands remotely.

References: `rsh man page: <https://manpages.org/rsh>`_


.. _Proto_295:

`NDPI_PROTOCOL_1KXUN`
======================
1Kxun is a Chinese internet company offering web services.

References: `1Kxun official site: <https://1kxun.mobi/>`_


.. _Proto_296:

`NDPI_PROTOCOL_IP_PGM`
=======================
PGM is a reliable multicast transport protocol.

References: `RFC3208: <https://datatracker.ietf.org/doc/html/rfc3208>`_


.. _Proto_297:

`NDPI_PROTOCOL_IP_PIM`
=======================
PIM is a multicast routing protocol family for IP packets.

References: `RFC7761: <https://datatracker.ietf.org/doc/html/rfc7761>`_


.. _Proto_298:

`NDPI_PROTOCOL_COLLECTD`
=========================
Collectd gathers system and application metrics periodically.

References: `Collectd official site: <https://collectd.org>`_


.. _Proto_299:

`NDPI_PROTOCOL_TUNNELBEAR`
===========================
TunnelBear is a consumer VPN service.

References: `TunnelBear official site: <https://www.tunnelbear.com>`_


.. _Proto_300:

`NDPI_PROTOCOL_CLOUDFLARE_WARP`
================================
Cloudflare Warp offers secure VPN and DNS resolution.

References: `Cloudflare Warp: <https://one.one.one.one/>`_


.. _Proto_301:

`NDPI_PROTOCOL_I3D`
====================
i3d.net provides dedicated and cloud game servers.

References: `i3d.net official site: <https://www.i3d.net/>`_


.. _Proto_302:

`NDPI_PROTOCOL_RIOTGAMES`
=========================
Riot Games develops games like League of Legends and Valorant.

References: `Riot Games official site: <https://www.riotgames.com/>`_


.. _Proto_303:

`NDPI_PROTOCOL_PSIPHON`
========================
Psiphon circumvents internet censorship using VPN and proxy tech.

References: `Psiphon official site: <https://psiphon.ca/>`_


.. _Proto_304:

`NDPI_PROTOCOL_ULTRASURF`
=========================
UltraSurf bypasses firewalls and protects privacy via proxy.

References: `UltraSurf official site: <https://ultrasurf.us/>`_


.. _Proto_305:

`NDPI_PROTOCOL_THREEMA`
========================
Threema is a privacy-focused instant messaging app.

References: `Threema official site: <https://threema.ch/en>`_


.. _Proto_306:

`NDPI_PROTOCOL_ALICLOUD`
=========================
Alibaba Cloud offers cloud computing services.

References: `Alibaba Cloud official site: <https://www.alibabacloud.com/>`_


.. _Proto_307:

`NDPI_PROTOCOL_AVAST`
======================
Avast provides antivirus and internet security software.

References: `Avast official site: <https://www.avast.com/>`_


.. _Proto_308:

`NDPI_PROTOCOL_TIVOCONNECT`
============================
TiVo Connect enables streaming to TiVo set-top boxes.

References: `TiVo official site: <https://www.tivo.com/>`_


.. _Proto_309:

`NDPI_PROTOCOL_KISMET`
=======================
Kismet detects and monitors wireless networks.

References: `Kismet official site: <https://www.kismetwireless.net/>`_


.. _Proto_310:

`NDPI_PROTOCOL_FASTCGI`
========================
FastCGI interfaces programs with web servers to boost dynamic web app performance.

References: `FastCGI Archives: <https://fastcgi-archives.github.io/>`_


.. _Proto_311:

`NDPI_PROTOCOL_FTPS`
=====================
FTPS extends FTP with TLS/SSL for security.

References: `RFC4217: <https://datatracker.ietf.org/doc/html/rfc4217>`_


.. _Proto_312:

`NDPI_PROTOCOL_NATPMP`
=======================
NAT-PMP auto-configures port forwarding on NAT gateways.

References: `RFC6886: <https://datatracker.ietf.org/doc/html/rfc6886>`_


.. _Proto_313:

`NDPI_PROTOCOL_SYNCTHING`
==========================
Syncthing synchronizes files continuously between devices.

References: `Syncthing official site: <https://syncthing.net/>`_


.. _Proto_314:

`NDPI_PROTOCOL_CRYNET`
=======================
CryNetwork is CryEngine 5’s proprietary multiplayer protocol.

References: `CryEngine docs: <https://www.cryengine.com/docs/static/engines/cryengine-5/categories/23756813/pages/23308730>`_


.. _Proto_315:

`NDPI_PROTOCOL_LINE`
=====================
LINE is a messaging app with voice/video calls and social features.

References: `LINE official site: <https://line.me/en/>`_


.. _Proto_316:

`NDPI_PROTOCOL_LINE_CALL`
==========================
LINE Call offers free voice calls within LINE app.

References: `LINE official site: <https://line.me/en/>`_


.. _Proto_317:

`NDPI_PROTOCOL_APPLETVPLUS`
============================
Apple TV+ streams original shows and movies.

References: `Apple TV+ official site: <https://tv.apple.com/>`_


.. _Proto_318:

`NDPI_PROTOCOL_DIRECTV`
========================
DirecTV offers satellite TV and interactive services.

References: `DirecTV official site: <https://www.directv.com/>`_


.. _Proto_319:

`NDPI_PROTOCOL_HBO`
====================
HBO provides premium TV series, movies, and docs.

References: `HBO official site: <https://www.hbo.com/>`_


.. _Proto_320:

`NDPI_PROTOCOL_VUDU`
=====================
Vudu offers digital movies and TV rentals/purchases.

References: `Vudu official site: <https://www.vudu.com/>`_


.. _Proto_321:

`NDPI_PROTOCOL_SHOWTIME`
=========================
Showtime offers original series, movies, and sports programming.

References: `Showtime official site: <https://www.showtime.com/>`_


.. _Proto_322:

`NDPI_PROTOCOL_DAILYMOTION`
============================
Dailymotion is a video-sharing platform.

References: `Dailymotion official site: <https://www.dailymotion.com/>`_


.. _Proto_323:

`NDPI_PROTOCOL_LIVESTREAM`
===========================
Livestream enables live event broadcasting.

References: `Livestream official site: <https://livestream.com/>`_


.. _Proto_324:

`NDPI_PROTOCOL_TENCENTVIDEO`
=============================
Tencent Video streams movies, TV, and variety shows.

References: `Tencent Video official site: <https://v.qq.com/>`_


.. _Proto_325:

`NDPI_PROTOCOL_IHEARTRADIO`
=============================
iHeartRadio streams music and radio stations.

References: `iHeartRadio official site: <https://www.iheart.com/>`_


.. _Proto_326:

`NDPI_PROTOCOL_TIDAL`
======================
Tidal offers high-fidelity music streaming.

References: `Tidal official site: <https://tidal.com/>`_


.. _Proto_327:

`NDPI_PROTOCOL_TUNEIN`
=======================
TuneIn streams live news, radio, and podcasts.

References: `TuneIn official site: <https://tunein.com/>`_


.. _Proto_328:

`NDPI_PROTOCOL_SIRIUSXMRADIO`
==============================
SiriusXM offers satellite and online radio services.

References: `SiriusXM official site: <https://www.siriusxm.com/>`_


.. _Proto_329:

`NDPI_PROTOCOL_MUNIN`
=====================
Munin visualizes network and system resource metrics.

References: `Munin official site: <http://munin-monitoring.org/>`_


.. _Proto_330:

`NDPI_PROTOCOL_ELASTICSEARCH`
==============================
Elasticsearch is a distributed search and analytics engine.

References: `Elastic official site: <https://www.elastic.co/elasticsearch/>`_


.. _Proto_331:

`NDPI_PROTOCOL_TUYA_LP`
========================
TUYA LAN Protocol enables local IoT device communication.

References: `GitHub - Tuya SDK: <https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n>`_


.. _Proto_332:

`NDPI_PROTOCOL_TPLINK_SHP`
===========================
TP-LINK Smart Home Protocol for local device control.

References: `Home Assistant TP-Link Integration: <https://www.home-assistant.io/integrations/tplink/>`_


.. _Proto_333:

`NDPI_PROTOCOL_SOURCE_ENGINE`
==============================

Source Engine protocol (A2S) is Valve's UDP-based game server query protocol.

References: `Valve Developer Wiki: <https://developer.valvesoftware.com/wiki/Server_queries>`_

Notes:

- Modern Valve games use Steam Datagram Relay (SDR) instead.


.. _Proto_334:

`NDPI_PROTOCOL_BACNET`
=======================
BACnet provides building automation and control communications.

References: `ASHRAE Standard 135-2016: <https://www.ashrae.org/technical-resources/bookstore/bacnet>`_


.. _Proto_335:

`NDPI_PROTOCOL_OICQ`
====================
OICQ is an early name for Tencent’s QQ instant messaging protocol.

References: `Tencent QQ Wikipedia: <https://en.wikipedia.org/wiki/Tencent_QQ>`_


.. _Proto_336:

`NDPI_PROTOCOL_HOTS`
====================
Heroes of the Storm (HOTS) is a MOBA game by Blizzard.

References: `HOTS official site: <https://heroesofthestorm.blizzard.com/>`_


.. _Proto_337:

`NDPI_PROTOCOL_FACEBOOK_REEL_STORY`
====================================
Facebook Reel Story relates to story clip streaming on Facebook.

References: `Facebook help: <https://www.facebook.com/help/1026380301307372>`_


.. _Proto_338:

`NDPI_PROTOCOL_SRTP`
=====================
SRTP provides encryption and authentication for RTP streams.

References: `RFC3711: <https://datatracker.ietf.org/doc/html/rfc3711>`_

Notes:

- SRTP is essentially "encrypted RTP", similar to HTTPS vs HTTP.
- Differentiating RTP from SRTP is often difficult; nDPI uses SRTP only when confident.


.. _Proto_339:

`NDPI_PROTOCOL_OPERA_VPN`
==========================
Opera VPN is a free VPN bundled with Opera Browser.

References: `Opera VPN feature: <https://www.opera.com/it/features/free-vpn>`_


.. _Proto_340:

`NDPI_PROTOCOL_EPICGAMES`
==========================
Epic Games develops Unreal Engine and games like Fortnite.

References: `Epic Games Store: <https://store.epicgames.com/en-US/>`_, `Fortnite: <https://www.fortnite.com/>`_


.. _Proto_341:

`NDPI_PROTOCOL_GEFORCENOW`
===========================
GeForce Now is Nvidia’s cloud gaming service.

References: `GeForce Now official site: <https://www.nvidia.com/en-us/geforce-now/>`_


.. _Proto_342:

`NDPI_PROTOCOL_NVIDIA`
=======================
Generic traffic from Nvidia sites.

References: `Nvidia official site: <https://www.nvidia.com>`_


.. _Proto_343:

`NDPI_PROTOCOL_BITCOIN`
========================
Bitcoin is a prominent cryptocurrency.

References: `Bitcoin Protocol documentation: <https://en.bitcoin.it/wiki/Protocol_documentation>`_

Notes:

- Crypto exchanges are not always mining; could be transactions or blockchain exploration.
- Bitcoin protocol governs node communication and block synchronization.


.. _Proto_344:

`NDPI_PROTOCOL_PROTONVPN`
==========================
Proton VPN is a VPN service by Proton AG.

References: `ProtonVPN official site: <https://protonvpn.com/>`_


.. _Proto_345:

`NDPI_PROTOCOL_THRIFT`
=======================
Apache Thrift is a cross-language data interchange framework.

References: `Thrift official site: <https://thrift.apache.org>`_, `Thrift Github: <https://github.com/apache/thrift>`_


.. _Proto_346:

`NDPI_PROTOCOL_ROBLOX`
=======================
Roblox is an online game platform and creation system.

References: `Roblox official site: <https://www.roblox.com/>`_

Notes:

- Roblox traffic may appear as RakNet since it uses a custom version.


.. _Proto_347:

`NDPI_PROTOCOL_SERVICE_LOCATION`
=================================
Service Location Protocol enables device service discovery on local networks.

References: `SLPv1: <https://datatracker.ietf.org/doc/html/rfc2165>`_, `SLPv2: <https://datatracker.ietf.org/doc/html/rfc2608>`_


.. _Proto_348:

`NDPI_PROTOCOL_MULLVAD`
========================
Mullvad VPN service operated by Mullvad VPN AB, Sweden.

References: `Mullvad official site: <https://mullvad.net/>`_


.. _Proto_349:

`NDPI_PROTOCOL_HTTP2`
======================
HTTP/2 is a major revision of the HTTP protocol.

References: `RFC9113: <https://datatracker.ietf.org/doc/html/rfc9113>`_

Notes:

- HTTP/2 is almost always transported over TLS (encrypted).


.. _Proto_350:

`NDPI_PROTOCOL_HAPROXY`
========================
HAProxy is a high availability load balancer and reverse proxy.

References: `HAProxy official site: <https://www.haproxy.org>`_


.. _Proto_351:

`NDPI_PROTOCOL_RMCP`
=====================
Intelligent Platform Management Interface (IPMI) RMCP protocol.

References: `IPMI specs: <https://www.dmtf.org/sites/default/files/standards/documents/DSP0114.pdf>`_


.. _Proto_352:

`NDPI_PROTOCOL_CAN`
====================
Controller Area Network (CAN) for automotive applications.

References: `ISO CAN standard: <https://www.iso.org/standard/63648.html>`_


.. _Proto_353:

`NDPI_PROTOCOL_PROTOBUF`
=========================
Protocol Buffers is a structured data serialization format.

References: `Protobuf encoding guide: <https://protobuf.dev/programming-guides/encoding>`_


.. _Proto_354:

`NDPI_PROTOCOL_ETHEREUM`
=========================
Ethereum is a decentralized blockchain with smart contract support.

References: `Ethereum docs: <https://ethereum.org/en/developers/docs/intro-to-ethereum/>`_

Notes:

- Similar to Bitcoin, not all exchanges represent mining; may be transactions or blockchain queries.


.. _Proto_355:

`NDPI_PROTOCOL_TELEGRAM_VOIP`
==============================
Telegram audio/video call protocol.

References: `Telegram Wikipedia: <https://en.wikipedia.org/wiki/telegram_(software)/>`_


.. _Proto_356:

`NDPI_PROTOCOL_SINA_WEIBO`
============================
Chinese microblogging site Sina Weibo.

References: `Sina Weibo Wikipedia: <https://en.wikipedia.org/wiki/Sina_Weibo>`_


.. _Proto_358:

`NDPI_PROTOCOL_PTPV2`
============================
IEEE 1588-2008 Precision Time Protocol Version 2.

References: `IEEE PTP specs: <https://standards.ieee.org/ieee/1588/4355/>`_


.. _Proto_359:

`NDPI_PROTOCOL_RTPS`
============================
Real-Time Publish Subscribe Protocol.

References: `RTPS specs: <https://www.omg.org/spec/DDSI-RTPS/>`_


.. _Proto_360:

`NDPI_PROTOCOL_OPC_UA`
============================
IEC62541 OPC Unified Architecture protocol.

References: `OPC Foundation: <https://reference.opcfoundation.org/>`_


.. _Proto_361:

`NDPI_PROTOCOL_S7COMM_PLUS`
============================
Siemens proprietary protocol for PLC data exchange (different from classic S7Comm).

References: `Protocol description: <https://plc4x.apache.org/protocols/s7/s7comm-plus.html>`_


.. _Proto_362:

`NDPI_PROTOCOL_FINS`
============================
Factory Interface Network Service (FINS) protocol used by Omron PLCs.

References: `Omron FINS docs: <https://assets.omron.eu/downloads/manual/en/v4/w421_cj1w-etn21_cs1w-etn21_ethernet_units_-_construction_of_applications_operation_manual_en.pdf>`_


.. _Proto_363:

`NDPI_PROTOCOL_ETHERSIO`
============================
Ether-S-I/O protocol used by Saia-Burgess PLCs.

References: `Wireshark EtherSIO wiki: <https://wiki.wireshark.org/EtherSIO.md>`_


.. _Proto_364:

`NDPI_PROTOCOL_UMAS`
============================
UMAS is Schneider Electric's proprietary protocol based on Modbus.

References: `Analysis: <https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/>`_


.. _Proto_365:

`NDPI_PROTOCOL_BECKHOFF_ADS`
=============================
Automation Device Specification protocol for Beckhoff PLCs.

References: `Beckhoff ADS docs: <https://infosys.beckhoff.com/english.php?content=../content/1033/tc3_ads_intro/115847307.html>`_


.. _Proto_366:

`NDPI_PROTOCOL_ISO9506_1_MMS`
==============================
Manufacturing Message Specification (MMS) protocol for device remote control.

References: `ISO 9506-1:2003 standard (paid): <https://www.iso.org/ru/standard/37079.html>`_


.. _Proto_367:

`NDPI_PROTOCOL_IEEE_C37118`
============================
IEEE standard for Synchrophasor Data Transfer.

References: `IEEE C37.118.1-2011 standard (paid): <https://standards.ieee.org/ieee/C37.118.1/4902/>`_


.. _Proto_368:

`NDPI_PROTOCOL_ETHERSBUS`
============================
Ether-S-Bus protocol for Saia-Burgess PLC communication.

References: `Wireshark EtherSBus wiki: <https://wiki.wireshark.org/EtherSBus>`_


.. _Proto_369:

`NDPI_PROTOCOL_MONERO`
======================
Monero is a privacy-focused cryptocurrency.

(No references)


.. _Proto_370:

`NDPI_PROTOCOL_DCERPC`
======================
DCE/RPC is a remote procedure call mechanism specification.

References: `Wireshark DCE/RPC wiki: <https://wiki.wireshark.org/DCE/RPC>`_


.. _Proto_371:

`NDPI_PROTOCOL_PROFINET_IO`
============================
PROFINET/IO is a field bus protocol based on connectionless DCE/RPC.

References: `PROFINET specs: <https://www.profibus.com/download/profinet-specification>`_


.. _Proto_372:

`NDPI_PROTOCOL_HISLIP`
=======================
HiSLIP is for remote control of LAN-based test and measurement instruments.

References: `HiSLIP specs: <https://www.ivifoundation.org/downloads/Protocol%20Specifications/IVI-6.1_HiSLIP-2.0-2020-04-23.pdf>`_


.. _Proto_373:

`NDPI_PROTOCOL_UFTP`
=====================
Encrypted UDP based FTP with multicast.

References: `UFTP protocol: <https://uftp-multicast.sourceforge.net/protocol.txt>`_


.. _Proto_374:

`NDPI_PROTOCOL_OPENFLOW`
=========================
OpenFlow is a network protocol associated with Software-Defined Networking.

References: `OpenFlow specs: <https://opennetworking.org/wp-content/uploads/2014/10/openflow-switch-v1.5.1.pdf>`_


.. _Proto_375:

`NDPI_PROTOCOL_JSON_RPC`
=========================
JSON-RPC is a remote procedure call protocol encoded in JSON.

References: `JSON-RPC specs: <https://www.jsonrpc.org/specification>`_


.. _Proto_376:

`NDPI_PROTOCOL_WEBDAV`
======================
WebDAV extends HTTP to collaboratively edit and manage files on Web servers.

References: `RFC4918: <https://datatracker.ietf.org/doc/html/rfc4918>`_

Notes:

- WebDAV is mostly transported over TLS (encrypted).


.. _Proto_377:

`NDPI_PROTOCOL_APACHE_KAFKA`
============================
Apache Kafka is a distributed event streaming platform.

References: `Kafka official site: <https://kafka.apache.org>`_, `Kafka Github: <https://github.com/apache/kafka>`_


.. _Proto_378:

`NDPI_PROTOCOL_NOMACHINE`
==========================
NoMachine is a proprietary remote desktop software.

References: `NoMachine official site: <https://www.nomachine.com/>`_


.. _Proto_379:

`NDPI_PROTOCOL_IEC62056`
============================
IEC 62056-4-7 DLMS/COSEM transport layer for IP.

References: `IEC paid specs: <https://webstore.iec.ch/publication/22487>`_

Notes:

- Wireshark does not support this protocol; some old code available at: 
  `<https://github.com/bearxiong99/wireshark-dlms>`, `<https://github.com/matousp/dlms-analysis/tree/master>`


.. _Proto_380:

`NDPI_PROTOCOL_HL7`
=========================
HL7 standards for clinical and administrative health data exchange.

References: `HL7 official site: <https://www.hl7.org/>`_


.. _Proto_381:

`NDPI_PROTOCOL_CEPH`
=========================
Ceph is a scalable distributed storage system.

References: `Ceph official site: <https://ceph.io/en/>`_


.. _Proto_382:

`NDPI_PROTOCOL_GOOGLE_CHAT`
============================
Google Chat is Google’s instant messaging service, successor to Hangouts.

References: `Google Chat official site: <https://chat.google.com/>`_


.. _Proto_383:

`NDPI_PROTOCOL_ROUGHTIME`
=========================
Protocol for rough time sync with cryptographic server verification.

References: `IETF Draft: <https://www.ietf.org/archive/id/draft-ietf-ntp-roughtime-08.html>`_


.. _Proto_384:

`NDPI_PROTOCOL_PIA`
=========================
Private Internet Access (PIA) VPN service.

References: `PIA official site: <https://www.privateinternetaccess.com/>`_


.. _Proto_385:

`NDPI_PROTOCOL_KCP`
===================
KCP is a fast, reliable protocol supporting TCP-like streams with low latency.

References: `KCP protocol spec: <https://github.com/skywind3000/kcp/blob/master/protocol.txt>`_


.. _Proto_386:

`NDPI_PROTOCOL_DOTA2`
=========================
Dota 2 is a popular multiplayer MOBA game by Valve.

References: `Dota 2 official site: <https://www.dota2.com/>`_


.. _Proto_387:

`NDPI_PROTOCOL_MUMBLE`
=========================
Mumble is a free, low-latency, high-quality voice chat app.

References: `Mumble official site: <https://www.mumble.info/>`_


.. _Proto_388:

`NDPI_PROTOCOL_YOJIMBO`
========================
Yojimbo is a secure client/server UDP-based protocol.

References: `Protocol spec: <https://github.com/mas-bandwidth/netcode/blob/main/STANDARD.md>`_


.. _Proto_389:

`NDPI_PROTOCOL_ELECTRONICARTS`
===============================
Electronic Arts is a major game publisher and producer.

References: `EA official site: <https://www.ea.com/>`_

Notes:

- Much of the traffic relates to EA Origin game store.


.. _Proto_390:

`NDPI_PROTOCOL_STOMP`
========================
STOMP is an interoperable protocol for asynchronous message passing.

References: `STOMP specification: <https://stomp.github.io/stomp-specification-1.2.html>`_


.. _Proto_391:

`NDPI_PROTOCOL_RADMIN`
=========================
Radmin is remote access software for Windows.

References: `Radmin official site: <https://www.radmin.com/>`_


.. _Proto_392:

`NDPI_PROTOCOL_RAFT`
=====================
Raft is a consensus protocol for distributed logs.

References: `Raft C implementation: <https://github.com/canonical/raft>`_, `Raft paper: <https://raft.github.io/raft.pdf>`_


.. _Proto_394:

`NDPI_PROTOCOL_GEARMAN`
========================
Gearman is a network job-queuing system.

References: `Gearman official site: <http://gearman.org/>`_


.. _Proto_395:

`NDPI_PROTOCOL_TENCENTGAMES`
=============================
Protocol used by Tencent's various games (mostly mobile).

References: `Tencent Games official site: <https://www.tencentgames.com/>`_


.. _Proto_396:

`NDPI_PROTOCOL_GAIJIN`
=======================
Gaijin Entertainment games protocols.

References: `Gaijin official site: <https://gaijin.net/>`_


.. _Proto_397:

`NDPI_PROTOCOL_C1222`
=====================
ANSI C12.22 protocol for communication with electric meters.

References: `NEMA standard (paid): <https://www.nema.org/Standards/view/American-National-Standard-for-Protocol-Specification-for-Interfacing-to-Data-Communication-Networks/>`_


.. _Proto_398:

`NDPI_PROTOCOL_HUAWEI`
======================
Generic traffic related to Huawei.

References: `Huawei official site: <https://www.huawei.com/>`_


.. _Proto_399:

`NDPI_PROTOCOL_HUAWEI_CLOUD`
============================
Huawei Mobile Cloud services.

References: `Huawei Cloud: <https://cloud.huawei.com/>`_


.. _Proto_400:

`NDPI_PROTOCOL_DLEP`
=====================
Dynamic Link Exchange Protocol (DLEP) supports radio-aware routing.

References: `RFC8175: <https://datatracker.ietf.org/doc/html/rfc8175>`_


.. _Proto_401:

`NDPI_PROTOCOL_BFD`
=====================
Bidirectional Forwarding Detection detects faults between routers or switches.

References: `RFC5880: <https://datatracker.ietf.org/doc/html/rfc5880>`_


.. _Proto_402:

`NDPI_PROTOCOL_NETEASE_GAMES`
=============================
Traffic from NetEase games.

References: `NetEase Games official site: <https://www.neteasegames.com/>`_


.. _Proto_403:

`NDPI_PROTOCOL_PATHOFEXILE`
============================
Path of Exile is a free online action RPG.

References: `Path of Exile official site: <https://pathofexile.com/>`_


.. _Proto_404:

`NDPI_PROTOCOL_GOOGLE_CALL`
============================
Google audio/video call applications (e.g., Google Meet).

References: `Google Meet official site: <https://meet.google.com/>`_

Notes:

- nDPI uses different IDs for generic and realtime traffic (e.g., NDPI_PROTOCOL_MEET vs NDPI_PROTOCOL_GOOGLE_CALL).


.. _Proto_405:

`NDPI_PROTOCOL_PFCP`
=====================
PFCP protocol communicates between control and user planes in 4G/5G.

References: `PFCP specs: <https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/16.05.00_60/ts_129244v160500p.pdf>`_


.. _Proto_406:

`NDPI_PROTOCOL_FLUTE`
======================
File Delivery over Unidirectional Transport protocol.

References: `RFC6726: <https://datatracker.ietf.org/doc/html/rfc6726>`_


.. _Proto_407:

`NDPI_PROTOCOL_LOLWILDRIFT`
============================
League of Legends: Wild Rift mobile MOBA game.

References: `Wild Rift official site: <https://wildrift.leagueoflegends.com/>`_


.. _Proto_408:

`NDPI_PROTOCOL_TESO`
============================
The Elder Scrolls Online MMORPG.

References: `ESO official site: <https://www.elderscrollsonline.com/>`_


.. _Proto_409:

`NDPI_PROTOCOL_LDP`
=====================
Label Distribution Protocol establishes label paths in MPLS.

References: `RFC5036: <https://datatracker.ietf.org/doc/html/rfc5036>`_


.. _Proto_410:

`NDPI_PROTOCOL_KNXNET_IP`
=========================
KNXnet/IP extends KNX home/building automation over IP.

References: `Standard docs (paid): <https://webstore.ansi.org/standards/ds/dsiso225102019>`_


.. _Proto_411:

`NDPI_PROTOCOL_BLUESKY`
=======================
Bluesky decentralized microblogging platform.

References: `Bluesky official site: <https://bsky.app/>`_


.. _Proto_412:

`NDPI_PROTOCOL_MASTODON`
========================
Mastodon is open-source software for self-hosted social networking.

References: `Mastodon official site: <https://joinmastodon.org/>`_


.. _Proto_413:

`NDPI_PROTOCOL_THREADS`
========================
Threads is a social media service by Meta.

References: `Threads official site: <https://www.threads.net>`_


.. _Proto_414:

`NDPI_PROTOCOL_VIBER_VOIP`
===========================
Viber audio/video call protocol.

References: `Viber Wikipedia: <https://en.wikipedia.org/wiki/Viber>`_


.. _Proto_415:

`NDPI_PROTOCOL_ZUG`
=========================
ZUG protocol is part of Casper 2.0 blockchain consensus.

References: `Casper Labs site: <https://casperlabs.io>`, `Casper blog: <https://casperlabs.io/blog/beyond-eth-30-theres-casper-20>`_


.. _Proto_416:

`NDPI_PROTOCOL_JRMI`
=========================
Java Remote Method Invocation protocol.

References: `Oracle JRMI docs: <https://docs.oracle.com/en/java/javase/21/docs/specs/rmi/protocol.html>`_


.. _Proto_417:

`NDPI_PROTOCOL_RIPE_ATLAS`
==========================
RIPE Atlas probe protocol for Internet measurement.

References: `RIPE Atlas site: <https://atlas.ripe.net/>`_, `RIPE Atlas docs: <https://ripe-atlas-tools.readthedocs.io/en/latest/index.html>`_


.. _Proto_418:

`NDPI_PROTOCOL_HLS`
=====================
HTTP Live Streaming (HLS) segments media for adaptive streaming.

References: `RFC8216: <https://datatracker.ietf.org/doc/html/rfc8216>`_


.. _Proto_419:

`NDPI_PROTOCOL_CLICKHOUSE`
===========================
ClickHouse is a columnar database for OLAP.

References: `ClickHouse official site: <https://clickhouse.com/>`_


.. _Proto_420:

`NDPI_PROTOCOL_NANO`
======================
Nano is a fast, fee-less, eco-friendly cryptocurrency.

References: `Nano official site: <https://nano.org/>`_


.. _Proto_421:

`NDPI_PROTOCOL_OPENWIRE`
========================
OpenWire is Apache ActiveMQ’s wire protocol.

References: `OpenWire docs: <https://activemq.apache.org/components/classic/documentation/openwire>`_


.. _Proto_422:

`NDPI_PROTOCOL_CNP_IP`
======================
Encapsulation of LonWorks control network over IP.

References: `ISO/IEC 14908-4:2012 standard (paid): <https://www.iso.org/standard/60206.html>`_


.. _Proto_423:

`NDPI_PROTOCOL_ATG`
===================
Automatic Tank Gauge system data transfer protocol.

References: `ATG protocol specs: <https://github.com/Orange-Cyberdefense/awesome-industrial-protocols/blob/main/protocols/atg.md>`_


.. _Proto_424:

`NDPI_PROTOCOL_TRDP`
====================
Train Real Time Data Protocol standardized by IEC.

References: `TRDP specs: <https://www.typhoon-hil.com/documentation/typhoon-hil-software-manual/References/iec_61375_trdp_protocol.html>`_


.. _Proto_425:

`NDPI_PROTOCOL_LUSTRE`
======================
Lustre is a parallel distributed file system for supercomputing.

References: `Lustre official site: <https://www.lustre.org/>`_


.. _Proto_426:

`NDPI_PROTOCOL_NORDVPN`
=======================
NordVPN is a VPN service.

References: `NordVPN official site: <https://nordvpn.com>`_


.. _Proto_427:

`NDPI_PROTOCOL_SURFSHARK`
=========================
Surfshark VPN service.

References: `Surfshark official site: <https://surfshark.com/>`_


.. _Proto_428:

`NDPI_PROTOCOL_CACTUSVPN`
=========================
CactusVPN service.

References: `CactusVPN official site: <https://cactusvpn.com/>`_


.. _Proto_429:

`NDPI_PROTOCOL_WINDSCRIBE`
==========================
Windscribe VPN service.

References: `Windscribe official site: <https://windscribe.com/>`_


.. _Proto_430:

`NDPI_PROTOCOL_SONOS`
=========================
Sonos provides high-quality wireless sound systems.

References: `Sonos official site: <https://www.sonos.com/>`_


.. _Proto_431:

`NDPI_PROTOCOL_DINGTALK`
=========================
DingTalk is a collaboration platform by Alibaba.

References: `DingTalk official site: <https://www.dingtalk.com/en>`_


.. _Proto_432:

`NDPI_PROTOCOL_PALTALK`
=========================
Paltalk is a video chat and messaging app.

References: `Paltalk official site: <https://www.paltalk.com/>`_


.. _Proto_433:

`NDPI_PROTOCOL_NAVER`
=========================
Naver is South Korea's top search engine and platform.

References: `Naver official site: <https://www.naver.com/>`_


.. _Proto_434:

`NDPI_PROTOCOL_SHEIN`
=====================
Shein is a fast fashion retailer.

References: `Shein official site: <https://www.shein.com/>`_


.. _Proto_435:

`NDPI_PROTOCOL_TEMU`
====================
Temu is an online marketplace by PDD Holdings.

References: `Temu official site: <https://www.temu.com/>`_


.. _Proto_436:

`NDPI_PROTOCOL_TAOBAO`
======================
Taobao is a Chinese online shopping platform.

References: `Taobao official site: <https://www.taobao.com/>`_


.. _Proto_437:

`NDPI_PROTOCOL_MIKROTIK`
========================
MikroTik Neighbor Discovery Protocol (MNDP) finds compatible neighbor routers/switches.

References: `MikroTik official docs: <https://help.mikrotik.com/docs/spaces/ROS/pages/24805517/Neighbor+discovery/>`_


.. _Proto_438:

`NDPI_PROTOCOL_DICOM`
=====================
DICOM is a standard for medical image storage and transmission.

References: `DICOM Wikipedia article: <https://en.wikipedia.org/wiki/DICOM>`_


.. _Proto_439:

`NDPI_PROTOCOL_PARAMOUNTPLUS`
=============================
Paramount+ is a subscription video streaming service.

References: `Paramount+ official site: <https://www.paramountplus.com/>`_


.. _Proto_440:

`NDPI_PROTOCOL_YANDEX_ALICE`
============================
Yandex Alice voice assistant, similar to Alexa.

References: `Yandex Alice protocol: <https://yandex.ru/dev/dialogs/alice/doc/ru/protocol/>`_


.. _Proto_441:

`NDPI_PROTOCOL_VIVOX`
=====================
Vivox provides real-time voice and text chat for games.

References: `Vivox official site: <https://unity.com/products/vivox-voice-chat>`_


.. _Proto_442:

`NDPI_PROTOCOL_DIGITALOCEAN`
============================
DigitalOcean cloud service provider.

References: `DigitalOcean official site: <https://www.digitalocean.com/>`_


.. _Proto_443:

`NDPI_PROTOCOL_RUTUBE`
============================
RUTUBE is a Russian video streaming platform.

References: `Rutube official site: <http://rutube.ru/>`_


.. _Proto_444:

`NDPI_PROTOCOL_LAGOFAST`
========================
LagoFast Game Booster improves gaming performance by reducing lag.

References: `LagoFast official site: <https://www.lagofast.com/>`_


.. _Proto_445:

`NDPI_PROTOCOL_GEARUP_BOOSTER`
==============================
GearUp Booster reduces game lag.

References: `GearUp Booster official site: <https://www.gearupbooster.com/>`_


.. _Proto_446:

`NDPI_PROTOCOL_LLM`
===================
Traffic related to various Large Language Models (ChatGPT, DeepSeek, Gemini, etc.)

References: `OpenAI: <https://openai.com/>`_, `DeepSeek: <https://www.deepseek.com/>`_


.. _Proto_447:

`NDPI_PROTOCOL_UBIQUITY`
========================
Traffic from Ubiquity sites and services.

References: `Ubiquity official site: <https://www.ui.com/>`_


.. _Proto_448:

`NDPI_PROTOCOL_MSDO`
========================
Microsoft Delivery Optimization distributes Windows updates and content.

References: `Microsoft DO docs: <https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization>`_


.. _Proto_449:

`NDPI_PROTOCOL_ROCKSTAR_GAMES`
===============================
Traffic related to Rockstar Games services and launcher.

References: `Rockstar Games official site: <https://www.rockstargames.com/>`_


.. _Proto_450:

`NDPI_PROTOCOL_KICK`
========================
Kick.com live streaming platform.

References: `Kick official site: <https://kick.com/>`_
