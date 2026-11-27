---
title: "nDPI Flow Risks"
description: "nDPI is designed not just to detect application protocols in traffic flows but also to evaluate potential security risks associated with the traffic. In..."
outline: [2, 3]
---
# nDPI Flow Risks {#ndpi-flow-risks}

nDPI is designed not just to detect application protocols in traffic flows but also to evaluate potential security risks associated with the traffic. In nDPI parlance this is called a "flow risk". Flows can have multiple risks detected hence nDPI reports them with a bitmap. Each risk detected corresponds to a bit in the flow risk bitmap. You can read more about [ndpi_risk_enum](https://github.com/ntop/nDPI/blob/dev/src/include/ndpi_typedefs.h) for the list of all numeric risks currently supported.

Below you can find a description of each flow risk so that you can easily understand when a risk is triggered and its meaning. The flow risks are listed in numerical order as they are defined in ndpi_risk_enum.


<a id="risk-001"></a>

## NDPI_URL_POSSIBLE_XSS {#ndpi-url-possible-xss}

HTTP only: this risk indicates a possible [XSS (Cross Side Scripting)](https://en.wikipedia.org/wiki/Cross-site_scripting) attack.


<a id="risk-002"></a>

## NDPI_URL_POSSIBLE_SQL_INJECTION {#ndpi-url-possible-sql-injection}

HTTP only: this risk indicates a possible [SQL Injection attack](https://en.wikipedia.org/wiki/SQL_injection).


<a id="risk-003"></a>

## NDPI_URL_POSSIBLE_RCE_INJECTION {#ndpi-url-possible-rce-injection}

HTTP only: this risk indicates a possible [RCE (Remote Code Execution) attack](https://en.wikipedia.org/wiki/Arbitrary_code_execution).


<a id="risk-004"></a>

## NDPI_BINARY_APPLICATION_TRANSFER {#ndpi-binary-application-transfer}

HTTP only: this risk indicates that a binary application is downloaded/uploaded. Detected applications include Windows binaries, Linux executables, Unix scripts and Android apps.


<a id="risk-005"></a>

## NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT {#ndpi-known-protocol-on-non-standard-port}

This risk indicates a known protocol used on a non standard port. Example HTTP is supposed to use TCP/80, and in case it is detected on TCP/1234 this risk is detected.


<a id="risk-006"></a>

## NDPI_TLS_SELFSIGNED_CERTIFICATE {#ndpi-tls-selfsigned-certificate}

TLS/QUIC only: this risk is triggered when a [self-signed certificate](https://en.wikipedia.org/wiki/Self-signed_certificate) is used.


<a id="risk-007"></a>

## NDPI_TLS_OBSOLETE_VERSION {#ndpi-tls-obsolete-version}

Risk triggered when TLS version is older than 1.1.


<a id="risk-008"></a>

## NDPI_TLS_WEAK_CIPHER {#ndpi-tls-weak-cipher}

Risk triggered when an unsafe TLS cipher is used. See [this page](https://community.qualys.com/thread/18212-how-does-qualys-determine-the-server-cipher-suites) for a list of insecure ciphers.


<a id="risk-009"></a>

## NDPI_TLS_CERTIFICATE_EXPIRED {#ndpi-tls-certificate-expired}

Risk triggered when a TLS certificate is expired, i.e. the current date falls outside of the certificate validity dates.


<a id="risk-010"></a>

## NDPI_TLS_CERTIFICATE_MISMATCH {#ndpi-tls-certificate-mismatch}

Risk triggered when a TLS certificate does not match the hostname we're accessing. Example you do <http://www.aaa.com> and the TLS certificate returned is for www.bbb.com.


<a id="risk-011"></a>

## NDPI_HTTP_SUSPICIOUS_USER_AGENT {#ndpi-http-suspicious-user-agent}

HTTP only: this risk is triggered whenever the user agent contains suspicious characters or its format is suspicious. Example: \&lt;?php something ?> is a typical suspicious user agent.


<a id="risk-012"></a>

## NDPI_NUMERIC_IP_HOST {#ndpi-numeric-ip-host}

This risk is triggered whenever a HTTP/TLS/QUIC connection is using a literal IPv4 or IPv6 address as ServerName (TLS/QUIC; example: SNI=1.2.3.4) or as Hostname (HTTP; example: <http://1.2.3.4>.).


<a id="risk-013"></a>

## NDPI_HTTP_SUSPICIOUS_URL {#ndpi-http-suspicious-url}

HTTP only: this risk is triggered whenever the accessed URL is suspicious. Example: <http://127.0.0.1/msadc/..%255c../..%255c../..%255c../winnt/system32/cmd.exe>.


<a id="risk-014"></a>

## NDPI_HTTP_SUSPICIOUS_HEADER {#ndpi-http-suspicious-header}

HTTP only: this risk is triggered whenever the HTTP header contains suspicious entries such as Uuid, TLS_version, Osname that are unexpected on the HTTP header.


<a id="risk-015"></a>

## NDPI_TLS_NOT_CARRYING_HTTPS {#ndpi-tls-not-carrying-https}

TLS only: this risk indicates that this TLS flow will not be used to transport HTTP content. Example VPNs use TLS to encrypt data rather to carry HTTP. This is useful to spot this type of cases.


<a id="risk-016"></a>

## NDPI_SUSPICIOUS_DGA_DOMAIN {#ndpi-suspicious-dga-domain}

A [DGA](https://en.wikipedia.org/wiki/Domain_generation_algorithm) is used to generate domain names often used by malwares. This risk indicates that this domain name can (but it's not 100% sure) a DGA as its name is suspicious.


<a id="risk-017"></a>

## NDPI_MALFORMED_PACKET {#ndpi-malformed-packet}

This risk is generated when a packet (e.g. a DNS packet) has an unexpected format. This can indicate a protocol error or more often an attempt to jeopardize a valid protocol to carry other type of data.


<a id="risk-018"></a>

## NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER {#ndpi-ssh-obsolete-client-version-or-cipher}

This risk is generated whenever a SSH client uses an obsolete SSH protocol version or insecure ciphers.


<a id="risk-019"></a>

## NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER {#ndpi-ssh-obsolete-server-version-or-cipher}

This risk is generated whenever a SSH server uses an obsolete SSH protocol version or insecure ciphers.


<a id="risk-020"></a>

## NDPI_SMB_INSECURE_VERSION {#ndpi-smb-insecure-version}

This risk indicates that the [SMB](https://en.wikipedia.org/wiki/Server_Message_Block) version used is insecure (i.e. v1).


<a id="risk-021"></a>

## NDPI_MISMATCHING_PROTOCOL_WITH_IP {#ndpi-mismatching-protocol-with-ip}

This risk indicates that the nDPI protocol detected for this flow (e.g. Facebook), does not resolve to a numeric flow server IP address that matches the known IPs for such protocol (in the above example the IP address do not belong to Facebook/Meta).


<a id="risk-022"></a>

## NDPI_UNSAFE_PROTOCOL {#ndpi-unsafe-protocol}

This risk indicates that the protocol used is insecure and that a secure protocol should be used (e.g. Telnet vs SSH).


<a id="risk-023"></a>

## NDPI_DNS_SUSPICIOUS_TRAFFIC {#ndpi-dns-suspicious-traffic}

This risk is returned when DNS traffic returns an unexpected/obsolete [record type](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
or when a suspicious query with a very long host name is detected.


<a id="risk-024"></a>

## NDPI_TLS_MISSING_SNI {#ndpi-tls-missing-sni}

TLS needs to carry the [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication) of the remote server we're accessing. Unfortunately SNI is optional in TLS so it can be omitted. In this case this risk is triggered as this is a non-standard situation that indicates a potential security problem or a protocol using TLS for other purposes (or a protocol bug).


<a id="risk-025"></a>

## NDPI_HTTP_SUSPICIOUS_CONTENT {#ndpi-http-suspicious-content}

HTTP only: risk reported when HTTP carries content in expected format. Example the HTTP header indicates that the context is text/html but the real content is not readeable (i.e. it can transport binary data). In general this is an attempt to use a valid MIME type to carry data that does not match the type.


<a id="risk-026"></a>

## NDPI_RISKY_ASN {#ndpi-risky-asn}

This is a placeholder for traffic exchanged with [ASN](<https://en.wikipedia.org/wiki/Autonomous_system_(Internet)>) that are considered risky. nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).


<a id="risk-027"></a>

## NDPI_RISKY_DOMAIN {#ndpi-risky-domain}

This is a placeholder for traffic exchanged with domain names that are considered risky. nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).


<a id="risk-028"></a>

## NDPI_MALICIOUS_FINGERPRINT {#ndpi-malicious-fingerprint}

This risk indicates that the Fingerprint of the TLS connection is considered suspicious. nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).


<a id="risk-029"></a>

## NDPI_MALICIOUS_SHA1_CERTIFICATE {#ndpi-malicious-sha1-certificate}

TLS certificates are uniquely identified with a [SHA1](https://en.wikipedia.org/wiki/SHA-1) hash value. If such hash is found on a blacklist, this risk can be used. As for other risks, this is a placeholder as nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).


<a id="risk-030"></a>

## NDPI_DESKTOP_OR_FILE_SHARING_SESSION {#ndpi-desktop-or-file-sharing-session}

This risk is set when the flow carries desktop or file sharing sessions (e.g. TeamViewer or AnyDesk just to mention two).


<a id="risk-031"></a>

## NDPI_TLS_UNCOMMON_ALPN {#ndpi-tls-uncommon-alpn}

This risk is set when the [ALPN](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation) (it indicates the protocol carried into this TLS flow, for instance HTTP/1.1) is uncommon with respect to the list of expected values.


<a id="risk-032"></a>

## NDPI_TLS_CERT_VALIDITY_TOO_LONG {#ndpi-tls-cert-validity-too-long}

From 01/09/2020 TLS certificates lifespan is limited to [13 months](https://www.appviewx.com/blogs/tls-certificate-lifespans-now-capped-at-13-months/). This risk is triggered for certificates not respecting this directive.


<a id="risk-033"></a>

## NDPI_TLS_SUSPICIOUS_EXTENSION {#ndpi-tls-suspicious-extension}

This risk is triggered when the domain name (SNI extension) is not printable and thus it is a problem. In TLS extensions can be dynamically specified by the client in the hello packet.


<a id="risk-034"></a>

## NDPI_TLS_FATAL_ALERT {#ndpi-tls-fatal-alert}

This risk is triggered when a TLS fatal alert is detected in the TLS flow. See [this page](https://techcommunity.microsoft.com/t5/iis-support-blog/ssl-tls-alert-protocol-and-the-alert-codes/ba-p/377132) for details.


<a id="risk-035"></a>

## NDPI_SUSPICIOUS_ENTROPY {#ndpi-suspicious-entropy}

This risk is used to detect suspicious data carried in ICMP packets whose entropy (used to measure how data is distributed, hence to indirectly guess the type of data carried on) is suspicious and thus that it can indicate a data leak. Suspicious values indicate random entropy or entropy that is similar to encrypted traffic. In the latter case, this can be a suspicious data exfiltration symptom.


<a id="risk-036"></a>

## NDPI_CLEAR_TEXT_CREDENTIALS {#ndpi-clear-text-credentials}

Clear text protocols are not intrinsically bad, but they should be avoided when they carry credentials as they can be intercepted by malicious users. This risk is triggered whenever clear text protocols (e.g. FTP, HTTP, IMAP...) contain credentials in clear text (read it as nDPI does not trigger this risk for HTTP connections that do not carry credentials).


<a id="risk-037"></a>

## NDPI_DNS_LARGE_PACKET {#ndpi-dns-large-packet}

[DNS](https://en.wikipedia.org/wiki/Domain_Name_System) packets over UDP should be limited to 512 bytes. DNS packets over this threshold indicate a potential security risk (e.g. use DNS to carry data) or a misconfiguration.


<a id="risk-038"></a>

## NDPI_DNS_FRAGMENTED {#ndpi-dns-fragmented}

UDP [DNS](https://en.wikipedia.org/wiki/Domain_Name_System) packets cannot be fragmented. If so, this indicates a potential security risk (e.g. use DNS to carry data) or a misconfiguration.


<a id="risk-039"></a>

## NDPI_INVALID_CHARACTERS {#ndpi-invalid-characters}

The risk is set whenever a dissected protocol contains characters not allowed in that protocol field.
For example a DNS hostname must only contain a subset of all printable characters or else this risk is set.
Additionally, some TLS protocol fields are checked for printable characters as well.


<a id="risk-040"></a>

## NDPI_POSSIBLE_EXPLOIT {#ndpi-possible-exploit}

The risk is set whenever a possible exploit attempt (e.g. [Log4J/Log4Shell](https://en.wikipedia.org/wiki/Log4Shell)) is detected.


<a id="risk-041"></a>

## NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE {#ndpi-tls-certificate-about-to-expire}

The risk is set whenever a TLS certificate is close to the expiration date.


<a id="risk-042"></a>

## NDPI_PUNYCODE_IDN {#ndpi-punycode-idn}

The risk is set whenever a domain name is specified in IDN format as they are sometimes used in [IDN homograph attacks](https://en.wikipedia.org/wiki/IDN_homograph_attack).


<a id="risk-043"></a>

## NDPI_ERROR_CODE_DETECTED {#ndpi-error-code-detected}

The risk is set whenever an error code is detected in the underlying protocol (e.g. HTTP and DNS).


<a id="risk-044"></a>

## NDPI_HTTP_CRAWLER_BOT {#ndpi-http-crawler-bot}

The risk is set whenever a crawler/bot/robot has been detected


<a id="risk-045"></a>

## NDPI_ANONYMOUS_SUBSCRIBER {#ndpi-anonymous-subscriber}

The risk is set whenever the (source) IP address has been anonymized and it can't be used to identify the subscriber.
Example: the flow is generated by an iCloud-private-relay exit node.


<a id="risk-046"></a>

## NDPI_UNIDIRECTIONAL_TRAFFIC {#ndpi-unidirectional-traffic}

The risk is set whenever the flow has unidirectional traffic (typically no traffic on the server to client direction). THis
risk is not triggered for multicast/broadcast destinations.


<a id="risk-047"></a>

## NDPI_HTTP_OBSOLETE_SERVER {#ndpi-http-obsolete-server}

This risk is generated whenever a HTTP server uses an obsolete HTTP server version.


<a id="risk-048"></a>

## NDPI_PERIODIC_FLOW {#ndpi-periodic-flow}

This risk is generated whenever a flow is observed at a specific periodic pace (e.g. every 10 seconds).


<a id="risk-049"></a>

## NDPI_MINOR_ISSUES {#ndpi-minor-issues}

Minor packet/flow issues (e.g. DNS traffic with zero TTL) have been detected.


<a id="risk-050"></a>

## NDPI_TCP_ISSUES {#ndpi-tcp-issues}

Relevant TCP connection issues such as connection refused, scan, or probe attempt.


<a id="risk-051"></a>

## NDPI_UNRESOLVED_HOSTNAME {#ndpi-unresolved-hostname}

Risk set when talking (TLS, QUIC, HTTP) with a symbolic hostname not previously observed on a DNS resolution. Unless the resolution was not observed as it was performed before nDPI started, it can indicate fake hosts contacted.


<a id="risk-052"></a>

## NDPI_TLS_ALPN_SNI_MISMATCH {#ndpi-tls-alpn-sni-mismatch}

Invalid TLS ALPN/SNI mismatch. For instance ALPN advertises the flow as h2 (HTTP/2.0) and no SNI is reported.


<a id="risk-053"></a>

## NDPI_MALWARE_CONTACTED {#ndpi-malware-contacted}

Client contacted a server host labelled as malware.


<a id="risk-054"></a>

## NDPI_BINARY_DATA_TRANSFER {#ndpi-binary-data-transfer}

HTTP only: this risk indicates that a binary file/data application transfer (attempt).


<a id="risk-055"></a>

## NDPI_PROBING_ATTEMPT {#ndpi-probing-attempt}

Connection with no data exchaged that looks like a probing attempt.


<a id="risk-056"></a>

## NDPI_OBFUSCATED_TRAFFIC {#ndpi-obfuscated-traffic}

This risk is triggered when a connection is likely using some obfuscation technique to try to "look like" something else, hiding its true nature.


<a id="risk-057"></a>

## NDPI_SLOW_DOS {#ndpi-slow-dos}

This risk is triggered when a TCP connection is likely subject to slow DoS attacks.


<a id="risk-058"></a>

## NDPI_NON_PQC {#ndpi-non-pqc}

This risk is triggered when an encrypted stream (e.g. TLS, QUIC, SSH, IPSEC) is not using post-quantum cryptography algorithms.


<a id="risk-059"></a>

## NDPI_AI_INFERENCE_TRAFFIC {#ndpi-ai-inference-traffic}

This risk is triggered when TLS/HTTP traffic is likely to be used to access a self-hosted LLM based on applications with ac vLLM or llama.cpp


<a id="risk-060"></a>

## NDPI_NON_PQC_FLOW {#ndpi-non-pqc-flow}

For TLS, this risk is triggered only when an observed ClientHello is followed by a TLS 1.3 ServerHello that visibly negotiates a non-post-quantum key-exchange group. It is not set from a ClientHello advertisement, a server-only trace, or a HelloRetryRequest alone. The standardized ML-KEM hybrid groups from [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024) are treated as post-quantum. Flows where the handshake is incomplete, resumed with PSK-only, or otherwise does not expose a negotiated key-share are left unclassified.
