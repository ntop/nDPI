What's Inside
-------------

This directory contains list of IP addresses that are loaded
by ndpiReader with --protocols-list-dir <lists directory>

File Name Format
----------------

The file name format is <protocol id>_<string>.list
The protocol id list can be found in src/include/ndpi_protocol_ids.h

What A By-IP Entry Does
-----------------------

An entry here names a flow by its destination address: it fills the
proto_by_ip field of the flow (the CSV/JSON export, and the FPC field of the
text dump), which is what a consumer uses for flows DPI cannot name. It is
advisory - it does not overwrite the DPI verdict. In a capture of ChatGPT
traffic behind one NAT address, listing that address made 201 of 307 flows
"OpenAI" by IP, and 198 of those stayed DNS flows, with mDNS and ICMP among
the rest: the granularity of the entry IS the precision of the attribution.

Ship an entry only when the addresses belong to the service. Anthropic serves
its API from netblocks it publishes (499_anthropic.list). Many providers sit
behind a CDN - on 2026-10-23, dig api.openai.com resolved to 172.66.0.243 and
162.159.140.245 (Cloudflare) and api.deepseek.com to a
d3bbv8sr76az5s.cloudfront.net CNAME (CloudFront) - and listing CDN space
labels every tenant of that CDN as the provider. Such providers get no file:
their flows are named by SNI, and under ECH by the DNS name the client
resolved, not by address.

Two Silences
------------

The namespace is not checked. ../ (this file's directory) is
<categoryId>_<string>.list and holds DOMAINS, loaded with -G; this directory
is <protocolId>_<string>.list and holds ADDRESSES, loaded with
--protocols-list-dir. A file in the wrong directory is accepted with no
warning and no effect, and so is a hostname written in an address list:
a file called 498_openai.list in ../ is read as "domains of category 498",
which is not a category. Verify by looking at proto_by_ip in the export,
never by the absence of an error message.

