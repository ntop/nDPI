nDPI Flow Risks
###############

nDPI is designed not just to detect application protocols in traffic flows but also to evaluate potential security risks associated with the traffic. In nDPI parlance this is called a "flow risk". Flows can have multiple risks detected hence nDPI reports them with a bitmap. Each risk detected corresponds to a bit in the flow risk bitmap. You can read more about `ndpi_risk_enum <https://github.com/ntop/nDPI/blob/dev/src/include/ndpi_typedefs.h>`_ for the list of all numeric risks currently supported.

Below you can find a description of each flow risk so that you can easily understand when a risk is triggered and its meaning. The flow risks are listed in numerical order as they are defined in ndpi_risk_enum.

.. _Risk 001:

NDPI_URL_POSSIBLE_XSS
=====================
HTTP only: this risk indicates a possible `XSS (Cross Side Scripting) <https://en.wikipedia.org/wiki/Cross-site_scripting>`_ attack.

.. _Risk 002:

NDPI_URL_POSSIBLE_SQL_INJECTION
===============================
HTTP only: this risk indicates a possible `SQL Injection attack <https://en.wikipedia.org/wiki/SQL_injection>`_.

.. _Risk 003:

NDPI_URL_POSSIBLE_RCE_INJECTION
===============================
HTTP only: this risk indicates a possible `RCE (Remote Code Execution) attack <https://en.wikipedia.org/wiki/Arbitrary_code_execution>`_.

.. _Risk 004:

NDPI_BINARY_APPLICATION_TRANSFER
================================
HTTP only: this risk indicates that a binary application is downloaded/uploaded. Detected applications include Windows binaries, Linux executables, Unix scripts and Android apps.

.. _Risk 005:

NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT
========================================
This risk indicates a known protocol used on a non standard port. Example HTTP is supposed to use TCP/80, and in case it is detected on TCP/1234 this risk is detected.

.. _Risk 006:

NDPI_TLS_SELFSIGNED_CERTIFICATE
===============================
TLS/QUIC only: this risk is triggered when a `self-signed certificate <https://en.wikipedia.org/wiki/Self-signed_certificate>`_ is used.

.. _Risk 007:

NDPI_TLS_OBSOLETE_VERSION
=========================
Risk triggered when TLS version is older than 1.1.

.. _Risk 008:

NDPI_TLS_WEAK_CIPHER
====================
Risk triggered when an unsafe TLS cipher is used. See `this page <https://community.qualys.com/thread/18212-how-does-qualys-determine-the-server-cipher-suites>`_ for a list of insecure ciphers.

.. _Risk 009:

NDPI_TLS_CERTIFICATE_EXPIRED
============================
Risk triggered when a TLS certificate is expired, i.e. the current date falls outside of the certificate validity dates.

.. _Risk 010:

NDPI_TLS_CERTIFICATE_MISMATCH
=============================
Risk triggered when a TLS certificate does not match the hostname we're accessing. Example you do http://www.aaa.com and the TLS certificate returned is for www.bbb.com.

.. _Risk 011:

NDPI_HTTP_SUSPICIOUS_USER_AGENT
===============================
HTTP only: this risk is triggered whenever the user agent contains suspicious characters or its format is suspicious. Example: <?php something ?> is a typical suspicious user agent.

.. _Risk 012:

NDPI_NUMERIC_IP_HOST
=========================
This risk is triggered whenever a HTTP/TLS/QUIC connection is using a literal IPv4 or IPv6 address as ServerName (TLS/QUIC; example: SNI=1.2.3.4) or as Hostname (HTTP; example: http://1.2.3.4.).

.. _Risk 013:

NDPI_HTTP_SUSPICIOUS_URL
========================
HTTP only: this risk is triggered whenever the accessed URL is suspicious. Example: http://127.0.0.1/msadc/..%255c../..%255c../..%255c../winnt/system32/cmd.exe.

.. _Risk 014:

NDPI_HTTP_SUSPICIOUS_HEADER
===========================
HTTP only: this risk is triggered whenever the HTTP peader contains suspicious entries such as Uuid, TLS_version, Osname that are unexpected on the HTTP header.

.. _Risk 015:

NDPI_TLS_NOT_CARRYING_HTTPS
===========================
TLS only: this risk indicates that this TLS flow will not be used to transport HTTP content. Example VPNs use TLS to encrypt data rather to carry HTTP. This is useful to spot this type of cases.

.. _Risk 016:

NDPI_SUSPICIOUS_DGA_DOMAIN
==========================
A `DGA <https://en.wikipedia.org/wiki/Domain_generation_algorithm>`_ is used to generate domain names often used by malwares. This risk indicates that this domain name can (but it's not 100% sure) a DGA as its name is suspicious.

.. _Risk 017:

NDPI_MALFORMED_PACKET
=====================
This risk is generated when a packet (e.g. a DNS packet) has an unexpected format. This can indicate a protocol error or more often an attempt to jeopardize a valid protocol to carry other type of data.

.. _Risk 018:

NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER
==========================================
This risk is generated whenever a SSH client uses an obsolete SSH protocol version or insecure ciphers.

.. _Risk 019:

NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER
==========================================
This risk is generated whenever a SSH server uses an obsolete SSH protocol version or insecure ciphers.

.. _Risk 020:

NDPI_SMB_INSECURE_VERSION
=========================
This risk indicates that the `SMB <https://en.wikipedia.org/wiki/Server_Message_Block>`_ version used is insecure (i.e. v1).

.. _Risk 021:

NDPI_TLS_SUSPICIOUS_ESNI_USAGE
==============================
`SNI <https://en.wikipedia.org/wiki/Server_Name_Indication>`_ is a way to carry in TLS the host/domain name we're accessing. ESNI means encrypted SNI and it is a way to mask SNI (carried in clear text in the TLS header) with encryption. While this practice is legal, it could be used for hiding data or for attacks such as a suspicious `domain fronting <https://github.com/SixGenInc/Noctilucent/blob/master/docs/>`_.

.. _Risk 022:

NDPI_UNSAFE_PROTOCOL
====================
This risk indicates that the protocol used is insecure and that a secure protocol should be used (e.g. Telnet vs SSH).

.. _Risk 023:

NDPI_DNS_SUSPICIOUS_TRAFFIC
===========================
This risk is returned when DNS traffic returns an unexpected/obsolete `record type <https://en.wikipedia.org/wiki/List_of_DNS_record_types>`_
or when a suspicious query with a very long host name is detected.

.. _Risk 024:

NDPI_TLS_MISSING_SNI
====================
TLS needs to carry the the `SNI <https://en.wikipedia.org/wiki/Server_Name_Indication>`_ of the remote server we're accessing. Unfortunately SNI is optional in TLS so it can be omitted. In this case this risk is triggered as this is a non-standard situation that indicates a potential security problem or a protocol using TLS for other purposes (or a protocol bug).

.. _Risk 025:

NDPI_HTTP_SUSPICIOUS_CONTENT
============================
HTTP only: risk reported when HTTP carries content in expected format. Example the HTTP header indicates that the context is text/html but the real content is not readeable (i.e. it can transport binary data). In general this is an attempt to use a valid MIME type to carry data that does not match the type.

.. _Risk 026:

NDPI_RISKY_ASN
==============
This is a placeholder for traffic exchanged with `ASN <https://en.wikipedia.org/wiki/Autonomous_system_(Internet)>`_ that are considered risky. nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).

.. _Risk 027:

NDPI_RISKY_DOMAIN
=================
This is a placeholder for traffic exchanged with domain names that are considered risky. nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).

.. _Risk 028:

NDPI_MALICIOUS_FINGERPRINT
==========================
This risk indicates that the Fingerprint of the TLS connection is considered suspicious. nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).

.. _Risk 029:

NDPI_MALICIOUS_SHA1_CERTIFICATE
===============================
TLS certificates are uniquely identified with a `SHA1 <https://en.wikipedia.org/wiki/SHA-1>`_ hash value. If such hash is found on a blacklist, this risk can be used. As for other risks, this is a placeholder as nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).

.. _Risk 030:

NDPI_DESKTOP_OR_FILE_SHARING_SESSION
====================================
This risk is set when the flow carries desktop or file sharing sessions (e.g. TeamViewer or AnyDesk just to mention two).

.. _Risk 031:

NDPI_TLS_UNCOMMON_ALPN
======================
This risk is set when the `ALPN <https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation>`_ (it indicates the protocol carried into this TLS flow, for instance HTTP/1.1) is uncommon with respect to the list of expected values.

.. _Risk 032:

NDPI_TLS_CERT_VALIDITY_TOO_LONG
===============================
From 01/09/2020 TLS certificates lifespan is limited to `13 months <https://www.appviewx.com/blogs/tls-certificate-lifespans-now-capped-at-13-months/>`_. This risk is triggered for certificates not respecting this directive.

.. _Risk 033:

NDPI_TLS_SUSPICIOUS_EXTENSION
=============================
This risk is triggered when the domain name (SNI extension) is not printable and thus it is a problem. In TLS extensions can be dynamically specified by the client in the hello packet.

.. _Risk 034:

NDPI_TLS_FATAL_ALERT
====================
This risk is triggered when a TLS fatal alert is detected in the TLS flow. See `this page <https://techcommunity.microsoft.com/t5/iis-support-blog/ssl-tls-alert-protocol-and-the-alert-codes/ba-p/377132>`_ for details.

.. _Risk 035:

NDPI_SUSPICIOUS_ENTROPY
=======================
This risk is used to detect suspicious data carried in ICMP packets whose entropy (used to measure how data is distributed, hence to indirectly guess the type of data carried on) is suspicious and thus that it can indicate a data leak. Suspicious values indicate random entropy or entropy that is similar to encrypted traffic. In the latter case, this can be a suspicious data exfiltration symptom.

.. _Risk 036:

NDPI_CLEAR_TEXT_CREDENTIALS
===========================
Clear text protocols are not intrinsically bad, but they should be avoided when they carry credentials as they can be intercepted by malicious users. This risk is triggered whenever clear text protocols (e.g. FTP, HTTP, IMAP...) contain credentials in clear text (read it as nDPI does not trigger this risk for HTTP connections that do not carry credentials).

.. _Risk 037:

NDPI_DNS_LARGE_PACKET
=====================
`DNS <https://en.wikipedia.org/wiki/Domain_Name_System>`_ packets over UDP should be limited to 512 bytes. DNS packets over this threshold indicate a potential security risk (e.g. use DNS to carry data) or a misconfiguration.

.. _Risk 038:

NDPI_DNS_FRAGMENTED
===================

UDP `DNS <https://en.wikipedia.org/wiki/Domain_Name_System>`_ packets cannot be fragmented. If so, this indicates a potential security risk (e.g. use DNS to carry data) or a misconfiguration.

.. _Risk 039:

NDPI_INVALID_CHARACTERS
=======================
The risk is set whenever a dissected protocol contains characters not allowed in that protocol field.
For example a DNS hostname must only contain a subset of all printable characters or else this risk is set.
Additionally, some TLS protocol fields are checked for printable characters as well.

.. _Risk 040:

NDPI_POSSIBLE_EXPLOIT
=====================
The risk is set whenever a possible exploit attempt (e.g. `Log4J/Log4Shell <https://en.wikipedia.org/wiki/Log4Shell>`_) is detected.

.. _Risk 041:

NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE
===================================
The risk is set whenever a TLS certificate is close to the expiration date.

.. _Risk 042:

NDPI_PUNYCODE_IDN
===================================
The risk is set whenever a domain name is specified in IDN format as they are sometimes used in `IDN homograph attacks <https://en.wikipedia.org/wiki/IDN_homograph_attack>`_.

.. _Risk 043:

NDPI_ERROR_CODE_DETECTED
===================================
The risk is set whenever an error code is detected in the underlying protocol (e.g. HTTP and DNS).

.. _Risk 044:

NDPI_HTTP_CRAWLER_BOT
===================================
The risk is set whenever a crawler/bot/robot has been detected

.. _Risk 045:

NDPI_ANONYMOUS_SUBSCRIBER
===================================
The risk is set whenever the (source) IP address has been anonymized and it can't be used to identify the subscriber.
Example: the flow is generated by an iCloud-private-relay exit node.

.. _Risk 046:

NDPI_UNIDIRECTIONAL_TRAFFIC
===================================
The risk is set whenever the flow has unidirectional traffic (typically no traffic on the server to client direction). THis
risk is not triggered for multicast/broadcast destinations.

.. _Risk 047:

NDPI_HTTP_OBSOLETE_SERVER
===================================
This risk is generated whenever a HTTP server uses an obsolete HTTP server version.

.. _Risk 048:

NDPI_PERIODIC_FLOW
==================
This risk is generated whenever a flow is observed at a specific periodic pace (e.g. every 10 seconds).

.. _Risk 049:

NDPI_MINOR_ISSUES
=================
Minor packet/flow issues (e.g. DNS traffic with zero TTL) have been detected.

.. _Risk 050:

NDPI_TCP_ISSUES
===============
Relevant TCP connection issues such as connection refused, scan, or probe attempt.

.. _Risk 051

NDPI_FULLY_ENCRYPTED
====================
Flow with Unknown protocol containing encrypted traffic.

.. _Risk 052

NDPI_TLS_ALPN_SNI_MISMATCH
=========================
Invalid TLS ALPN/SNI mismatch. For instance ALPN advertises the flow as h2 (HTTP/2.0) and no SNI is reported.

.. _Risk 053

NDPI_MALWARE_CONTACTED
======================
Client contacted a server host labelled as malware.

.. _Risk 054:

NDPI_BINARY_DATA_TRANSFER
============================
HTTP only: this risk indicates that a binary file/data application transfer (attempt).

.. _Risk 055:

NDPI_PROBING_ATTEMPT
====================
Connection with no data exchaged that looks like a probing attempt

.. _Risk 056:

NDPI_OBFUSCATED_TRAFFIC
=======================
This risk is triggered when a connection is likely using some obfuscation technique to try to "look like" something else, hiding its true nature
