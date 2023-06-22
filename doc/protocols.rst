nDPI Protocols List
####################

This page provides the list of the protocols/applications supported by nDPI. For each protocol there is a brief description, some links to further, more detailed information and, optionally, some notes that might be useful when handling such a protocol (from the application/integrator point of view)

Work in progress!

.. _Proto 338:

`NDPI_PROTOCOL_SRTP`: SRTP (Secure Real-time Transport Protocol)
================================================================
The Secure Real-time Transport Protocol (SRTP) is a profile for Real-time Transport Protocol (RTP) intended to provide encryption, message authentication, integrity, and replay attack protection to the RTP data.

References: `RFC3711 <https://datatracker.ietf.org/doc/html/rfc3711>`_.

Notes:

- You can think of SRTP simply as the "encrypted" version of RTP, something like HTTPS vs HTTP;
- It is not usually possible to tell RTP from SRTP. nDPI generally uses the former and it uses the latter only when it is really sure that the media stream has been encrypted.


.. _Proto 340:

`NDPI_PROTOCOL_EPICGAMES`
=========================
Epic Games is a video game company developing the Unreal Engine and some successful games as Fortnite and Gears of War.

References: `Main site <https://store.epicgames.com/en-US/>`_ `Fortnite <https://www.fortnite.com/>`_.


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
======================
Bitcoin is one of the most common crypto currencies.

References: `Main site <https://en.bitcoin.it/wiki/Protocol_documentation>`_.

Notes:

- Not each crypto exchange is a mining, it could be a normal transaction, sending or receving.
- Bitcoin network protocol covers the broader set of rules that govern how all nodes in the network communicate and sync with each others blocks and transactions. 
- On the other hand mining protocols are more specific and deal directly with how miners interact with the network and participate in the mining process.


.. _Proto 344:

`NDPI_PROTOCOL_PROTONVPN`
========================
Proton VPN is a VPN service operated by the Swiss company Proton AG, the company behind the email service Proton Mail

References: `Main site https://protonvpn.com/`


.. _Proto 345:

`NDPI_PROTOCOL_THRIFT`
========================
Apache Thrift is a generic data interchange framework that supports a bunch of different languages and platforms.

References: `Official site <https://thrift.apache.org>`_ `Github <https://github.com/apache/thrift>`_.
