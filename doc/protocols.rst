nDPI Protocols List
###################

This page provides the list of the protocols/applications supported by nDPI. For each protocol there is a brief description, some links to further, more detailed information and, optionally, some notes that might be useful when handling such a protocol (from the application/integrator point of view)

Work in progress!

.. _Proto 338:

`NDPI_PROTOCOL_SRTP`
====================
The Secure Real-time Transport Protocol (SRTP) is a profile for Real-time Transport Protocol (RTP) intended to provide encryption, message authentication, integrity, and replay attack protection to the RTP data.

References: `RFC3711 <https://datatracker.ietf.org/doc/html/rfc3711>`_.

Notes:

- You can think of SRTP simply as the "encrypted" version of RTP, something like HTTPS vs HTTP;
- It is not usually possible to tell RTP from SRTP. nDPI generally uses the former and it uses the latter only when it is really sure that the media stream has been encrypted.


.. _Proto 339:

`NDPI_PROTOCOL_OPERA_VPN`
=========================
Opera VPN is a free VPN included with Opera Browser.

References: `Main site <https://www.opera.com/it/features/free-vpn>`_.


.. _Proto 340:

`NDPI_PROTOCOL_EPICGAMES`
=========================
Epic Games is a video game company developing the Unreal Engine and some successful games as Fortnite and Gears of War.

References: `Main site <https://store.epicgames.com/en-US/>`_ and `Fortnite <https://www.fortnite.com/>`_.


.. _Proto 341:

`NDPI_PROTOCOL_GEFORCENOW`
==========================
GeForce Now is the brand used by Nvidia for its cloud gaming service.

References: `Main site <https://www.nvidia.com/en-us/geforce-now/>`_.


.. _Proto 342:

`NDPI_PROTOCOL_NVIDIA`
======================
Generic web traffic from Nvidia sites.

References: `Main site <https://www.nvidia.com>`_.


.. _Proto 343:

`NDPI_PROTOCOL_BITCOIN`
=======================
Bitcoin is one of the most common crypto currencies.

References: `Main site <https://en.bitcoin.it/wiki/Protocol_documentation>`_.

Notes:

- Not each crypto exchange is a mining, it could be a normal transaction, sending or receving.
- Bitcoin network protocol covers the broader set of rules that govern how all nodes in the network communicate and sync with each others blocks and transactions. 
- On the other hand mining protocols are more specific and deal directly with how miners interact with the network and participate in the mining process.


.. _Proto 344:

`NDPI_PROTOCOL_PROTONVPN`
=========================
Proton VPN is a VPN service operated by the Swiss company Proton AG, the company behind the email service Proton Mail

References: `Main site <https://protonvpn.com/>`_.


.. _Proto 345:

`NDPI_PROTOCOL_THRIFT`
======================
Apache Thrift is a generic data interchange framework that supports a bunch of different languages and platforms.

References: `Official site <https://thrift.apache.org>`_ and `Github <https://github.com/apache/thrift>`_.


.. _Proto 346:

`NDPI_PROTOCOL_ROBLOX`
======================
Roblox is an online game platform and game creation system.

References: `Main site <https://www.roblox.com/>`_.

Notes:

- Since Roblox games use a custom version of the RakNet protocol, some Roblox flows might be classified as RakNet.


.. _Proto 347:

`NDPI_PROTOCOL_SERVICE_LOCATION`
================================
The Service Location Protocol is a service discovery protocol that allows computers and other devices to find services in a local area network without prior configuration.

References: `SLPv1 <https://datatracker.ietf.org/doc/html/rfc2165>`_ and `SLPv2 <https://datatracker.ietf.org/doc/html/rfc2608>`_.


.. _Proto 348:

`NDPI_PROTOCOL_MULLVAD`
=======================
Mullvad is a VPN service operated by Mullvad VPN AB, based in Sweden

References: `Main site <https://mullvad.net/>`_.


.. _Proto 349:

`NDPI_PROTOCOL_HTTP2`
=====================
HTTP/2 (originally named HTTP/2.0) is a major revision of the HTTP network protocol used by the World Wide Web.

References: `RFC <https://datatracker.ietf.org/doc/html/rfc9113>`_.

Notes:

- HTTP/2 is almost always encrypted, i.e. transported over TLS.


.. _Proto 350:

`NDPI_PROTOCOL_HAPROXY`
=======================
HAProxy is a free and open source software that provides a high availability load balancer and reverse proxy for TCP and HTTP-based applications that spreads requests across multiple servers.

References: `Main site: <https://www.haproxy.org>`_.
