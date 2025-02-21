/*
MIT License

Copyright (c) 2023-24 Ivan Nardi <nardi.ivan@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <asm/byteorder.h>
#include <linux/ppp_defs.h>

#include "pl7m.h"

#if defined(__has_feature)
# if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#endif
#endif

#ifdef __cplusplus
extern "C"
#endif

/*	Configuration options/defines:
	* PL7M_ENABLE_ERROR: to enable logging of important/critical errors
	* PL7M_ENABLE_LOG: to enable verbose logging
	* PL7M_USE_INTERNAL_FUZZER_MUTATE: instead of using the standard function
	  `LLVMFuzzerMutate()` provided by libfuzz, use a custom/internal logic
	  to randomize the data. It is usefull if you want to use this code
	  without linking to libfuzz
	* PL7M_USE_SIMPLEST_MUTATOR: instead of fuzzing only the L7 part of the
	  packets, randomize the entire data. Note that the output of the
	  mutator will be a valid pcap file anyway
	* PL7M_DISABLE_PACKET_MUTATION: disable mutations at packet level (see
	  below). The output trace contains the same packets (in the same order
	  and with the same timestamp) of the input trace
	* PL7M_DISABLE_PAYLOAD_MUTATION: disable mutations at payload level
	  (see below)
	* PL7M_USE_64K_PACKETS: allow packets with maximum size (~64k) instead of
	  the standard size (~1526). Useful for handling TSO packets or for
	  checking integer overflow on u_int16_t variables (i.e. ip length...).
	  Note that this option might lead to significant bigger corpus

	Mutations happens at two different levels:
	* packet level: each packet might be dropped, duplicated, swapped or
	   its direction might be swapped (i.e. from client->server to server->client)
	* payload level: packet (L5/7) payload (i.e. data after TCP/UDP header)
	  is changed
*/



#ifndef IPPROTO_IPV4
#define IPPROTO_IPV4	4
#endif
#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF	89
#endif
#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP	112
#endif
#ifndef IPPROTO_PGM
#define IPPROTO_PGM	113
#endif

#ifdef PL7M_ENABLE_ERROR
#define derr(fmt, args...) \
	do { \
		fprintf(stderr, "" fmt, ## args);\
	} while (0)
#else
#define derr(fmt, args...) \
	do { \
	} while (0)
#endif

#ifdef PL7M_ENABLE_LOG
#define ddbg(fmt, args...) \
	do { \
		fprintf(stderr, "" fmt, ## args);\
	} while (0)
#else
#define ddbg(fmt, args...) \
	do { \
	} while (0)
#endif


#ifdef PL7M_USE_64K_PACKETS
#define MAX_PKT_LENGTH	(26 + 20 + 1024 * 64)	/* Max possible size: ethernet + ip(v4) + 64k ip payload */
#else
#define MAX_PKT_LENGTH	(26 + 1500)		/* "Standard" maximum packet size */
#endif

#ifndef PL7M_USE_INTERNAL_FUZZER_MUTATE
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
#endif


/* If you want custom memory allocators, you can simply change these defines */
#define pl7m_malloc(size)	malloc(size)
#define pl7m_calloc(num, size)	calloc(num, size)
#define pl7m_free(p)		free(p)



struct gre_header {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int16_t rec:3,
		  srr:1,
		  seq:1,
		  key:1,
		  routing:1,
		  csum:1,
		  version:3,
		  reserved:4,
		  ack:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u_int16_t csum:1,
		  routing:1,
		  key:1,
		  seq:1,
		  srr:1,
		  rec:3,
		  ack:1,
		  reserved:4,
		  version:3;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
    __u16	protocol;
};

#define GTP_MSG_TPDU	0xFF

struct gtp_header {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int16_t n_pdu:1,
		  sequence:1,
		  extension:1,
		  reserved:1,
		  protocol:1,
		  version:3,
		  type:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u_int16_t version:3,
		  protocol:1,
		  reserved:1,
		  extension:1,
		  sequence:1,
		  n_pdu:1,
		  type:8;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
	u_int16_t total_length;
	u_int32_t teid;
};

struct gtp_header_optional {
	u_int16_t sn;
	u_int8_t n_pdu_nbr;
	u_int8_t next_hdr;
};


struct m_pkt {
	unsigned char *raw_data;
	struct pcap_pkthdr header;

	int l2_offset;
	int prev_l3_offset;
	u_int16_t prev_l3_proto;
	int gtp_offset;
	int l3_offset;
	u_int16_t l3_proto;
	int l4_offset;
	u_int8_t l4_proto;
	int l4_length;
	int l5_offset;
	int l5_length;

	int is_l3_fragment;
	int skip_l4_dissection;
	int skip_payload_actions;

	struct m_pkt *next;
};
struct pl7m_handle {
	int datalink;

	struct m_pkt *head;
	struct m_pkt *tail;
};


/*
	Dissection code: START
*/

static int __is_datalink_supported(int datalink_type)
{
	switch(datalink_type) {
	case DLT_NULL:
	case DLT_EN10MB:
	case DLT_PPP:
	case DLT_C_HDLC:
	case DLT_RAW:
	case DLT_LINUX_SLL:
	case DLT_LINUX_SLL2:
	case DLT_IPV4:
	case DLT_IPV6:
	case DLT_PPI:
		return 1;
	default:
	return 0;
	}
}
static int __is_l3_proto_supported(int proto)
{
	switch(proto) {
	case ETH_P_IP:
	case ETH_P_IPV6:
	case ETH_P_ARP:
		/* TODO: add other protocols */
		return 1;
	default:
		return 0;
	}
}
static int dissect_l2(int datalink_type, struct m_pkt *p)
{
	int l2_offset, l3_offset;
	u_int16_t l3_proto = 0, next, header_length;
	u_int32_t dlt;
	unsigned char *data = p->raw_data;
	int data_len = p->header.caplen;

	if (data_len <= 0) {
		derr("Invalid len %d\n", data_len);
		return -1;
	}

	l2_offset = p->l2_offset;
	assert(l2_offset >= 0 && l2_offset < (int)p->header.caplen);

	switch(datalink_type) {
	case DLT_NULL:
		if (data_len < l2_offset + 5)
			return -1;
		l3_offset = l2_offset + 4;
		if ((data[l3_offset] & 0xF0) == 0x40)
			l3_proto = ETH_P_IP;
		else if ((data[l3_offset] & 0xF0) == 0x60)
			l3_proto = ETH_P_IPV6;
		break;

	case DLT_RAW:
		if (data_len < l2_offset + 1)
			return -1;
		l3_offset = l2_offset + 0;
		if ((data[l3_offset] & 0xF0) == 0x40)
			l3_proto = ETH_P_IP;
		else if ((data[l3_offset] & 0xF0) == 0x60)
			l3_proto = ETH_P_IPV6;
		break;

	case DLT_IPV4:
		l3_proto = ETH_P_IP;
		l3_offset = l2_offset + 0;
		break;

	case DLT_IPV6:
		l3_proto = ETH_P_IPV6;
		l3_offset = l2_offset + 0;
		break;

	case DLT_LINUX_SLL:
		if (data_len < l2_offset + 16)
			return -1;
		l3_proto = ntohs(*((u_int16_t *)&data[l2_offset + 14]));
		l3_offset = 16;
		break;

	case DLT_LINUX_SLL2:
		if (data_len < l2_offset + 20)
			return -1;
		l3_proto = ntohs(*((u_int16_t *)&data[l2_offset]));
		l3_offset = 20;
		break;

	case DLT_PPI:
		if (data_len < l2_offset + 8)
			return -1;
		header_length = le16toh(*(u_int16_t *)&data[l2_offset + 2]);
		dlt = le32toh(*(u_int32_t *)&data[l2_offset + 4]);
		if(dlt != DLT_EN10MB) /* Handle only standard ethernet, for the time being */
			return -1;
		p->l2_offset += header_length;
		if (p->l2_offset >= (int)p->header.caplen)
			return -1;
		return dissect_l2(dlt, p);

	case DLT_PPP:
	case DLT_C_HDLC:
		if (data[l2_offset + 0] == 0x0f || data[l2_offset + 0] == 0x8f) {
			if (data_len < l2_offset + 4)
				return -1;
			l3_offset = 4;
			l3_proto = ntohs(*((u_int16_t *)&data[l2_offset + 2]));
		} else {
			if (data_len < l2_offset + 2)
				return -1;
			l3_offset = l2_offset + 2;
			next = ntohs(*((u_int16_t *)&data[l2_offset + 0]));
			switch (next) {
			case 0x0021:
				l3_proto = ETH_P_IP;
				break;
			case 0x0057:
				l3_proto = ETH_P_IPV6;
				break;
			default:
				derr("Unknown next proto on ppp 0x%x\n", next);
				return -1;
			}
		}
		break;

	case DLT_EN10MB:
		if (data_len < l2_offset + 14)
			return -1;
		l3_offset = l2_offset + 14;
		l3_proto = ntohs(*((u_int16_t *)&data[l3_offset - 2]));

		/* VLAN */
		while (l3_proto == 0x8100 && l3_offset + 4 < data_len) {
			l3_offset += 4;
			l3_proto = ntohs(*((u_int16_t *)&data[l3_offset - 2]));
		}

		/* PPPoES */
		if (l3_proto == 0x8864) {
			if (data_len < l3_offset + 8)
				return -1;
			l3_offset += 8;
			next = ntohs(*((u_int16_t *)&data[l3_offset - 2]));
			switch (next) {
			case 0x0021:
				l3_proto = ETH_P_IP;
				break;
			case 0x0057:
				l3_proto = ETH_P_IPV6;
				break;
			default:
				derr("Unknown next proto on pppoes 0x%x\n", next);
				return -1;
			}
		}

		break;

	default:
		derr("Unknown datalink %d\n", datalink_type);
		return -1;
	}

	if (data_len < l3_offset) {
		derr("Invalid length %d < %d\n", data_len, l3_offset);
		return -1;
	}
	if (!__is_l3_proto_supported(l3_proto)) {
		derr("Unsupported l3_proto 0x%x\n", l3_proto);
		return -1;
	}
	p->l3_offset = l3_offset;
	p->l3_proto = l3_proto;

	return 0;
}
static int __is_l4_proto_supported(int proto)
{
	switch(proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	case IPPROTO_IGMP:
	case IPPROTO_VRRP:
	case IPPROTO_AH:
	case IPPROTO_ESP:
	case IPPROTO_SCTP:
	case IPPROTO_PGM:
	case IPPROTO_PIM:
	case IPPROTO_IPV4:
	case IPPROTO_IPV6:
	case IPPROTO_GRE:
	case IPPROTO_OSPF:
		/* TODO: add other protocols */
		return 1;
	default:
		return 0;
	}
}
static int dissect_l3(struct m_pkt *p)
{
	struct ip *ip4;
	struct ip6_hdr *ip6;
	struct ip6_ext *ipv6_opt;
	int num_eh, ip_hdr_len, l3_len;
	unsigned char *data = p->raw_data + p->l3_offset;
	int data_len = p->header.caplen - p->l3_offset;

	ddbg("L3: l3_proto %d data_len %d\n", p->l3_proto, data_len);

	if (data_len < 0)
		return -1;

	switch (p->l3_proto) {
	case ETH_P_IP:
		ip4 = (struct ip *)data;
		if (data_len < 20 /* min */ ||
		    ip4->ip_v != 4 ||
		    ip4->ip_hl < 5 ||
		    data_len < ip4->ip_hl * 4 ||
		    ntohs(ip4->ip_len) < ip4->ip_hl * 4) {
			derr("Wrong lengths %d %d %d\n", data_len, ip4->ip_hl,
			     ntohs(ip4->ip_len));
			return -1;
		}
		/* TODO: properly handle fragments */
		if ((ntohs(ip4->ip_off) & IP_MF) ||
		    (ntohs(ip4->ip_off) & IP_OFFMASK)) {
			ddbg("Fragment\n");
			p->is_l3_fragment = 1;
			p->skip_payload_actions = 1;
		}
		if (!__is_l4_proto_supported(ip4->ip_p)) {
			derr("Unsupported L4: %d\n", ip4->ip_p);
			return -1;
		}
		p->l4_proto = ip4->ip_p;
		p->l4_offset = p->l3_offset + ip4->ip_hl * 4;
		p->l4_length = ntohs(ip4->ip_len) - ip4->ip_hl * 4;
		break;

	case ETH_P_IPV6:
		ip6 = (struct ip6_hdr *)data;
		if (data_len < (int)sizeof(struct ip6_hdr))
			return -1;

		/* It may be a IPv6 Jumbograms but it is probably a
		   malformed packet */
		if (ip6->ip6_plen == 0) {
			derr("Invalid ext len\n");
			return -1;
		}

		ip_hdr_len = sizeof(struct ip6_hdr);
		l3_len = ntohs(ip6->ip6_plen) + ip_hdr_len;
		if (l3_len < ip_hdr_len || data_len < l3_len) {
			derr("Invalid ipv6 lengths %d %d %d\n",
			     l3_len, ip_hdr_len, data_len);
			return -1;
		}

		p->l4_proto = ip6->ip6_nxt;

		/* Extension header */
		num_eh = 0;
		while (p->l4_proto == IPPROTO_HOPOPTS ||
		       p->l4_proto == IPPROTO_DSTOPTS ||
		       p->l4_proto == IPPROTO_ROUTING ||
		       p->l4_proto == IPPROTO_AH ||
		       p->l4_proto == IPPROTO_FRAGMENT) {

			num_eh++;

			if (data_len < ip_hdr_len + (int)sizeof(struct ip6_ext)) {
				derr("Error ipv6 (a) %d %d\n", data_len, ip_hdr_len);
				return -1;
			}
			if (ip_hdr_len >= l3_len) {
				derr("Error ipv6 (b) %d %d\n", ip_hdr_len, l3_len);
				return -1;
			}
			/* RFC2460 4.1 . Hop-by-Hop Options header [..] is
			   restricted to appear immediately after an IPv6 header only */
			if (p->l4_proto == IPPROTO_HOPOPTS && num_eh != 1) {
				derr("Hop-by-Hop Options not first header\n");
				return -1;
			}

			ipv6_opt = (struct ip6_ext *)&data[ip_hdr_len];
			ip_hdr_len += sizeof(struct ip6_ext);
			ddbg("EH (%d) %d ip6e_len %d\n", num_eh, p->l4_proto,
			     ipv6_opt->ip6e_len);
			if (p->l4_proto == IPPROTO_AH) {
				/* RFC4302 2.2. Payload Length: This 8-bit
				   field specifies the length of AH in
				   32-bit words (4-byte units), minus "2". */
				ip_hdr_len += ipv6_opt->ip6e_len * 4;
			} else if (p->l4_proto == IPPROTO_HOPOPTS) {
				/* RFC2460 4.3. Hdr Ext Len: Length of the Hop-by-Hop
				   Options header in 8-octet units, not including
				   the first 8 octets */
				ip_hdr_len += (8 + ipv6_opt->ip6e_len * 8);
			} else if (p->l4_proto == IPPROTO_ROUTING) {
				/* RFC8200 4.4. Hdr Ext Len:  Length of the Routing
				   header in 8-octet units, not including the
				   first 8 octets. */
				ip_hdr_len += (8 + ipv6_opt->ip6e_len * 8);
			} else {
				if (p->l4_proto != IPPROTO_FRAGMENT) {
					ip_hdr_len += ipv6_opt->ip6e_len;
				} else {
					ip_hdr_len += 6;
					ddbg("Fragment IPv6\n");
					p->is_l3_fragment = 1;
					p->skip_payload_actions = 1;
				}
			}
			p->l4_proto = ipv6_opt->ip6e_nxt;

			if (ip_hdr_len >= l3_len) {
				derr("Error ipv6 (c) %d %d\n", ip_hdr_len, l3_len);
				return -1;
			}
		}

		if (!__is_l4_proto_supported(p->l4_proto)) {
			derr("Unsupported L4: %d\n", p->l4_proto);
			return -1;
		}
		p->l4_proto = ip6->ip6_nxt;
		p->l4_offset = p->l3_offset + ip_hdr_len;
		p->l4_length = ntohs(ip6->ip6_plen) - (ip_hdr_len - sizeof(struct ip6_hdr));
		break;

	case ETH_P_ARP:
		p->skip_l4_dissection = 1;
		p->skip_payload_actions = 1;
		break;

	default:
		assert(0);
	}
	return 0;
}
static int dissect_l4(struct m_pkt *p)
{
	struct udphdr *udp_h;
	struct tcphdr *tcp_h;
	struct gre_header *gre_h;
	unsigned char *data = p->raw_data + p->l4_offset;
	int data_len = p->header.caplen - p->l4_offset;
	int l4_hdr_len, rc;
	unsigned char *ppp_h;
	u_int16_t ppp_proto;

	ddbg("L4: l4_proto %d data_len %d l4_length %d\n",
	     p->l4_proto, data_len, p->l4_length);

	if (data_len < 0 || p->l4_length > data_len)
		return -1;

	if (p->is_l3_fragment) {
		ddbg("Skip L4 dissection because it is a fragment\n");
		return 0;
	}
	if (p->skip_l4_dissection) {
		ddbg("Skip L4 dissection\n");
		return 0;
	}

	switch(p->l4_proto) {
	case IPPROTO_UDP:
		udp_h = (struct udphdr *)data;
		if (p->l4_length < (int)sizeof(struct udphdr) ||
		    ntohs(udp_h->len) > p->l4_length ||
		    ntohs(udp_h->len) < sizeof(struct udphdr)) {
			derr("Unexpected udp len %u vs %u\n",
			     ntohs(udp_h->len), p->l4_length);
			return -1;
		}
		p->l5_offset = p->l4_offset + sizeof(struct udphdr);
		p->l5_length = ntohs(udp_h->len) - sizeof(struct udphdr);
		break;
	case IPPROTO_TCP:
		tcp_h = (struct tcphdr *)data;
		if (p->l4_length < (int)sizeof(struct tcphdr)) {
			derr("Unexpected tcp len %d\n", p->l4_length);
			return -1;
		}
		l4_hdr_len = tcp_h->doff << 2;
		if (l4_hdr_len < (int)sizeof(struct tcphdr) ||
		    l4_hdr_len > p->l4_length) {
			derr("Unexpected tcp len %u %u\n",
			     l4_hdr_len, p->l4_length);
			return -1;
		}
		p->l5_offset = p->l4_offset + l4_hdr_len;
		p->l5_length = p->l4_length - l4_hdr_len;
		break;

	case IPPROTO_IPV4: /* IP in IP tunnel */
	case IPPROTO_IPV6: /* IP in IP tunnel */
		if (p->prev_l3_proto == 0) {
			assert(p->prev_l3_offset == 0);
			p->prev_l3_proto = p->l3_proto;
			p->prev_l3_offset = p->l3_offset;
		} else {
			derr("More than 2 ip headers. Unsupported\n");
			return -1;
		}
		p->l3_offset = p->l4_offset;
		p->l3_proto = (p->l4_proto == IPPROTO_IPV4) ? ETH_P_IP : ETH_P_IPV6;
		rc = dissect_l3(p);
		if (rc != 0) {
			derr("Error dissect_l3 (second header)\n");
			return -1;
		}
		return dissect_l4(p);

	case IPPROTO_GRE:
		gre_h = (struct gre_header *)data;
		if (p->l4_length < (int)sizeof(struct gre_header)) {
			derr("Unexpected gre len %d\n", p->l4_length);
			return -1;
		}
		/* Check version. 0 = GRE, 1 = ENHANCED GRE (used for PPTP) */
		if ((gre_h->version != 0 && gre_h->version != 1) ||
		    (gre_h->version == 1 && ntohs(gre_h->protocol) != 0x880b)) {
			derr("Unexpected gre version %d\n", gre_h->version);
			return -1;
		}
		l4_hdr_len = sizeof(struct gre_header);
		if (gre_h->key)
			l4_hdr_len += 4;
		if (gre_h->seq)
			l4_hdr_len += 4;
		if (gre_h->csum || gre_h->routing)
			l4_hdr_len += 4;
		if (gre_h->ack)
			l4_hdr_len += 4;
		if (p->l4_length < l4_hdr_len) {
			derr("Unexpected gre len %d/%d\n", l4_hdr_len, p->l4_length);
			return -1;
		}

		if (p->prev_l3_proto == 0) {
			assert(p->prev_l3_offset == 0);
			p->prev_l3_proto = p->l3_proto;
			p->prev_l3_offset = p->l3_offset;
		} else {
			derr("More than 2 ip headers. Unsupported\n");
			return -1;
		}

		if (gre_h->version == 0) {
			p->l3_proto = ntohs(gre_h->protocol);
			if (p->l3_proto == 0 && l4_hdr_len == p->l4_length) {
				derr("GRE keepalive\n");
				return -1;
			}
			if (p->l3_proto != ETH_P_IP && p->l3_proto != ETH_P_IPV6) {
				derr("Invalid L3 after GRE: 0x%x\n", p->l3_proto);
				return -1;
			}
		} else {
			ppp_h = &data[l4_hdr_len];

			if (ppp_h[0] == 0xFF) { /* PPP HDLC encapsulation */
				if(p->l4_length < l4_hdr_len + 4) {
					derr("Unexpected gre ppp len %d/%d\n",
					     l4_hdr_len, p->l4_length);
					return -1;
				}
				ppp_proto = ntohs(*(u_int16_t *)(ppp_h + 2));
				l4_hdr_len += 4;
			} else {		/* Address and control are compressed */
				ppp_proto = ppp_h[0];
				l4_hdr_len += 1;
			}

			switch (ppp_proto) {
			case PPP_IP:
				p->l3_proto = ETH_P_IP;
				break;
			case PPP_IPV6:
				p->l3_proto = ETH_P_IPV6;
				break;
			default:
				derr("Unexpected ppp proto %d\n", ppp_proto);
				return -1;
			}
		}
		p->l3_offset = p->l4_offset + l4_hdr_len;
		rc = dissect_l3(p);
		if (rc != 0) {
			derr("Error dissect_l3 (after gre)\n");
			return -1;
		}
		return dissect_l4(p);

	default:
		/* Fuzz also the L4 header itself, but leave at least 1 byte:
		   this way, we will never have an empty ip4/6 header */
		if (p->l4_length == 0)
			return -1;
		p->l5_offset = p->l4_offset + 1;
		p->l5_length = p->l4_length - 1;
		break;
	}
	return 0;
}
static int is_gtp_u(unsigned char *gtp_buffer, int gtp_buffer_len,
		    const struct m_pkt *p, u_int16_t *l3_proto)
{
	struct gtp_header *gtp_h;
	struct udphdr *udp_h;
	uint16_t new_layer_len = 0;
	unsigned char sub_proto;

	if (p->l4_proto != IPPROTO_UDP ||
	    gtp_buffer_len < (int)sizeof(struct gtp_header))
		return 0;

	/* Only default port */
	udp_h = (struct udphdr *)(p->raw_data + p->l4_offset);
	if(udp_h->source != htons(2152) &&
	   udp_h->dest != htons(2152))
		return 0;

	gtp_h = (struct gtp_header *)gtp_buffer;

	if (gtp_h->version != 1 ||
	    gtp_h->type != GTP_MSG_TPDU ||
	    gtp_h->reserved != 0 ||
	    ntohs(gtp_h->total_length) > (gtp_buffer_len - sizeof(struct gtp_header))) {
		ddbg("Invalid gtp header: %d, 0x%x, 0x%0x, %d vs %d\n",
		     gtp_h->version, gtp_h->type, gtp_h->reserved,
		     ntohs(gtp_h->total_length), gtp_buffer_len);
		return 0;
	}

	new_layer_len = sizeof(struct gtp_header);

	/* Optional header version 1 */
	if (gtp_h->extension || gtp_h->sequence || gtp_h->n_pdu) {
		new_layer_len += sizeof(struct gtp_header_optional);

		if (gtp_buffer_len < new_layer_len)
			return 0;
	}
	if (gtp_h->extension) {
		unsigned int length = 0;

		while (new_layer_len < (gtp_buffer_len - 1)) {
			length = gtp_buffer[new_layer_len] << 2;
			new_layer_len += length;
			if (new_layer_len > gtp_buffer_len ||
			    gtp_buffer[new_layer_len - 1] == 0 || length == 0)
				break;
		}
		if (new_layer_len > gtp_buffer_len ||
		    gtp_buffer[new_layer_len - 1] != 0 ||
		    length == 0) {
			return 0;
		}
	}

	/* Trying to detect next proto. Code taken from wireshark */
	if (gtp_buffer_len < new_layer_len + 1)
		return 0;
	sub_proto = gtp_buffer[new_layer_len];
	if ((sub_proto >= 0x45) && (sub_proto <= 0x4e)) {
		/* This is most likely an IPv4 packet
		 * we can exclude 0x40 - 0x44 because the minimum header size is 20 octets
		 * 0x4f is excluded because PPP protocol type "IPv6 header compression"
		 * with protocol field compression is more likely than a plain
		 * IPv4 packet with 60 octet header size */
		*l3_proto = ETH_P_IP;
	} else if ((sub_proto & 0xf0) == 0x60) {
		/* This is most likely an IPv6 packet */
		*l3_proto = ETH_P_IPV6;
	} else {
		/* This seems to be a PPP packet */
                /* TODO: code not back-ported from wireshark yet*/
		return 0;
	}

	return new_layer_len;
}
static int dissect_l4_detunneling(struct m_pkt *p)
{
	unsigned char *data = p->raw_data + p->l5_offset;
	int data_len = p->header.caplen - p->l5_offset;
	u_int16_t next_l3_proto;
	int gtp_header_len, rc;

	ddbg("L4(detunel): l4_proto %d data_len %d l5_length %d\n",
	     p->l4_proto, data_len, p->l5_length);

	if (data_len < 0 || p->l5_length > data_len)
		return -1;

	/* TODO: try to handle tunnel over fragment */
	if (p->is_l3_fragment) {
		ddbg("Skip L4(detunnel) dissection because it is a fragment\n");
		return 0;
	}
	/* No reasons to detunnel if we skipped L4 dissection */
	if (p->skip_l4_dissection) {
		ddbg("Skip L4 dissection\n");
		return 0;
	}

	/* GTP detunneling: looking only for MSG T-PDU that carries
	   encapsulated data */
	gtp_header_len = is_gtp_u(data, data_len, p, &next_l3_proto);
	if (gtp_header_len > 0) {
		ddbg("Found GTP-U\n");
		if (p->prev_l3_proto == 0) {
			assert(p->prev_l3_offset == 0);
			p->prev_l3_proto = p->l3_proto;
			p->prev_l3_offset = p->l3_offset;
		} else {
			derr("Multiple tunnels. Unsupported\n");
			return -1;
		}
		assert(p->gtp_offset == 0);
		p->gtp_offset = p->l5_offset;
		p->l3_proto = next_l3_proto;
		p->l3_offset = p->l5_offset + gtp_header_len;
		rc = dissect_l3(p);
		if (rc != 0) {
			derr("Error dissect_l3 (after gtp)\n");
			return -1;
		}
		return dissect_l4(p);
	}

	/* "Normal" L4 traffic */
	return 0;
}
static int dissect_do(int datalink_type, struct m_pkt *p)
{
	int rc;

	rc = dissect_l2(datalink_type, p);
	if (rc != 0) {
		derr("Error dissect_l2\n");
		return -1;
	}
	rc = dissect_l3(p);
	if (rc != 0) {
		derr("Error dissect_l3\n");
		return -1;
	}
	rc = dissect_l4(p);
	if (rc != 0) {
		derr("Error dissect_l4\n");
		return -1;
	}
	/* Some kind of detunneling over L4 (usually over UDP). Example: GTP */
	rc = dissect_l4_detunneling(p);
	if (rc != 0) {
		derr("Error dissect_l5\n");
		return -1;
	}
	return 0;
}

/*
	Dissection code: END
*/


#ifdef PL7M_USE_INTERNAL_FUZZER_MUTATE
static size_t internal_FuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize)
{
	int r;
	unsigned char rand_byte;
	size_t new_len = Size, offset;

	r = rand();
	switch (r % 5) {
	case 0:
		ddbg("Payload action: unchange\n");
		new_len = Size;
		break;
	case 1:
		ddbg("Payload action: change one byte at a random location\n");
		if (Size > 0) {
			offset = rand() % Size;
			rand_byte =  rand() % 255;
			Data[offset] = rand_byte;
		}
		break;
	case 2:
		ddbg("Payload action: append zero bytes\n");
		new_len = rand() % MaxSize;
		if (new_len > Size)
			memset(&Data[Size], '\0', new_len - Size);
		else
			new_len = Size;
		break;
	case 3:
		ddbg("Payload action: add one random byte at random location\n");
		if (MaxSize >= Size + 1) {
			offset = Size == 0 ? 0 : rand() % Size;
			rand_byte =  rand() % 255;
			new_len = Size + 1;
			memmove(Data + offset + 1, Data + offset, Size - offset);
			Data[offset] = rand_byte;
		}
		break;
	case 4:
		ddbg("Payload action: remove one byte from a random location\n");
		if (Size > 0) {
			offset = rand() % Size;
			new_len = Size - 1;
			memmove(Data + offset, Data + offset + 1, Size - offset - 1);
		}
		break;
	}
	return new_len;
}
#endif

#ifndef PL7M_USE_SIMPLEST_MUTATOR
static void update_do_l7(struct m_pkt *p)
{
	struct udphdr *udp_h;
	struct tcphdr *tcp_h;
	struct gtp_header *gtp_h;
	size_t new_l5_len;
	int l4_header_len = 0;
	int l5_len_diff;
	struct ip *ip4;
	struct ip6_hdr *ip6;

	assert(p->l5_offset + p->l5_length <= (int)p->header.caplen);
	assert(p->header.caplen <= MAX_PKT_LENGTH);
#ifndef PL7M_USE_INTERNAL_FUZZER_MUTATE
	new_l5_len = LLVMFuzzerMutate(p->raw_data + p->l5_offset,
				      p->l5_length, MAX_PKT_LENGTH - p->l5_offset);
	/* It seems the MASAN returns false positives. The value from
	   LLVMFuzzerMutate needs to be treated as initialized.
	   See a similar report:
	   https://github.com/google/libprotobuf-mutator/pull/213/commits/51629aaf874b38c42f5dc8b970cdf9156895c7e3
	*/
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
	__msan_unpoison(p->raw_data + p->l5_offset, new_l5_len);
# endif
#endif

#else
	new_l5_len = internal_FuzzerMutate(p->raw_data + p->l5_offset,
					   p->l5_length,
					   MAX_PKT_LENGTH - p->l5_offset);
#endif
	l5_len_diff = new_l5_len - p->l5_length;
	ddbg("l5_len %u->%zu (%d)\n", p->l5_length, new_l5_len, l5_len_diff);

	switch (p->l4_proto) {
	case IPPROTO_UDP:
		l4_header_len = sizeof(struct udphdr);
		udp_h = (struct udphdr *)(p->raw_data + p->l4_offset);
		udp_h->len = htons(l4_header_len + new_l5_len);
		break;
	case IPPROTO_TCP:
		tcp_h = (struct tcphdr *)(p->raw_data + p->l4_offset);
		l4_header_len = tcp_h->doff << 2;
		/* TODO */
		break;
	default:
		l4_header_len = 1;
		break;
	}

	if (p->l3_proto == ETH_P_IP) {
		ip4 = (struct ip *)(p->raw_data + p->l3_offset);
		ip4->ip_len = htons(htons(ip4->ip_len) + l5_len_diff);
	} else {
		assert(p->l3_proto == ETH_P_IPV6);
		ip6 = (struct ip6_hdr *)(p->raw_data + p->l3_offset);
		ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) + l5_len_diff);
	}

	/* Update previous ip header */
	if(p->prev_l3_proto == ETH_P_IP) {
		ip4 = (struct ip *)(p->raw_data + p->prev_l3_offset);
		ip4->ip_len = htons(htons(ip4->ip_len) + l5_len_diff);

	} else if(p->prev_l3_proto == ETH_P_IPV6) {
		ip6 = (struct ip6_hdr *)(p->raw_data + p->prev_l3_offset);
		ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) + l5_len_diff);
	}

	/* Update GTP header */
	if (p->gtp_offset) {
		gtp_h = (struct gtp_header *)(p->raw_data + p->gtp_offset);
		gtp_h->total_length = htons(ntohs(gtp_h->total_length) + l5_len_diff);
		/* Update previous UDP header */
		assert(p->gtp_offset > (int)sizeof(struct udphdr));
		udp_h = (struct udphdr *)(p->raw_data + p->gtp_offset - sizeof(struct udphdr));
		udp_h->len = htons(ntohs(udp_h->len) + l5_len_diff);
	}

	p->l5_length = new_l5_len;
	ddbg("cap_len %u->%zu\n", p->header.caplen, p->l5_offset + new_l5_len);
	p->header.caplen = p->l5_offset + new_l5_len;
	p->header.len = p->header.caplen;
	assert(p->header.caplen <= MAX_PKT_LENGTH);
}
#endif

#ifdef PL7M_USE_SIMPLEST_MUTATOR
static void update_do_simplest(struct m_pkt *p)
{
	size_t new_len;

#ifndef PL7M_USE_INTERNAL_FUZZER_MUTATE
	new_len = LLVMFuzzerMutate(p->raw_data, p->header.caplen, MAX_PKT_LENGTH);
#else
	new_len = internal_FuzzerMutate(p->raw_data, p->header.caplen, MAX_PKT_LENGTH);
#endif

	p->header.caplen = new_len;
	p->header.len = p->header.caplen;
	assert(p->header.caplen <= MAX_PKT_LENGTH);
}
#endif

static void update_do(struct m_pkt *p)
{
#ifdef PL7M_USE_SIMPLEST_MUTATOR
	update_do_simplest(p);
#else
	update_do_l7(p);
#endif
}

static void swap_direction(struct m_pkt *p)
{
	struct udphdr *udp_h;
	u_int16_t tmp_port;

	/* Length fields don't change */

	if (p->skip_l4_dissection == 1)
		return;

	switch (p->l4_proto) {
	case IPPROTO_UDP:
		udp_h = (struct udphdr *)(p->raw_data + p->l4_offset);
		tmp_port = udp_h->source;
		udp_h->source = udp_h->dest;
		udp_h->dest = tmp_port;
		break;
	case IPPROTO_TCP:
		/* TODO */
		break;
	default:
		/* Nothing to do */
		break;
	}

	if (p->l3_proto == ETH_P_IP) {
		struct ip *ip4;
		struct in_addr tmp_ip4;

		ip4 = (struct ip *)(p->raw_data + p->l3_offset);
		tmp_ip4 = ip4->ip_src;
		ip4->ip_src = ip4->ip_dst;
		ip4->ip_dst = tmp_ip4;
	} else {
		struct ip6_hdr *ip6;
		struct in6_addr tmp_ip6;

		assert(p->l3_proto == ETH_P_IPV6);
		ip6 = (struct ip6_hdr *)(p->raw_data + p->l3_offset);
		tmp_ip6 = ip6->ip6_src;
		ip6->ip6_src = ip6->ip6_dst;
		ip6->ip6_dst = tmp_ip6;
	}

	/* We probably don't need to swap direction of previous
	   ip header (if any) */
}

static struct m_pkt *__dup_pkt(struct m_pkt *p)
{
	struct m_pkt *n;

	n = (struct m_pkt *)pl7m_malloc(sizeof(struct m_pkt));
	if (!n)
		return NULL;
	n->raw_data = (unsigned char *)pl7m_malloc(MAX_PKT_LENGTH);
	if(!n->raw_data) {
		pl7m_free(n);
		return NULL;
	}
	memcpy(n->raw_data, p->raw_data, p->header.caplen);
	n->header = p->header;
	n->l2_offset = p->l2_offset;
	n->prev_l3_offset = p->prev_l3_offset;
	n->prev_l3_proto = p->prev_l3_proto;
	n->gtp_offset = p->gtp_offset;
	n->l4_offset = p->l4_offset;
	n->l3_offset = p->l3_offset;
	n->l3_proto = p->l3_proto;
	n->l4_offset = p->l4_offset;
	n->l4_proto = p->l4_proto;
	n->l4_length = p->l4_length;
	n->l5_offset = p->l5_offset;
	n->l5_length = p->l5_length;
	n->is_l3_fragment = p->is_l3_fragment;
	n->skip_l4_dissection = p->skip_l4_dissection;
	n->skip_payload_actions = p->skip_payload_actions;
	n->next = NULL;
	return n;
}
static void __free_pkt(struct m_pkt *p)
{
	pl7m_free(p->raw_data);
	pl7m_free(p);
}
static void __add_pkt(struct pl7m_handle *h, struct m_pkt *p,
		      struct m_pkt *prev, struct m_pkt *next)
{
	if (prev) {
		prev->next = p;
	} else {
		h->head = p;
	}
	p->next = next;
	if(p->next == NULL)
		h->tail = p;
}
static void __del_pkt(struct pl7m_handle *h, struct m_pkt *p, struct m_pkt *prev)
{
	if (prev) {
		prev->next = p->next;
	} else {
		h->head = p->next;
	}
	__free_pkt(p);
}
static int __swap_pkt(struct pl7m_handle *h, struct m_pkt *p, struct m_pkt *prev,
		      struct m_pkt *next)
{
	struct timeval ts;

	if (!next)
		return 0;

	/* Swap timestamps too. If the original pcap is ordered (in time),
	   the mutated one will be, too */
	ts = next->header.ts;

	if (prev) {
		prev->next = next;
		next->header.ts = p->header.ts;
	} else {
		h->head = next;
	}
	p->next = next->next;
	next->next = p;
	p->header.ts = ts;

	/* TODO: update tail */

	return 1;
}

static void __free_m_pkts(struct pl7m_handle *h)
{
	struct m_pkt *p, *n;

	if (!h)
		return;
	p = h->head;
	while (p) {
		n = p->next;
		__free_pkt(p);
		p = n;
	}
	pl7m_free(h);
}

static struct m_pkt *do_pkt_actions(struct pl7m_handle *h, struct m_pkt *p, struct m_pkt **prev)
{
	int r;
	struct m_pkt *d, *tmp_prev;

	r = rand();
	switch (r % 4) {
	case 0: /* Drop */
		ddbg("Action drop\n");
		__del_pkt(h, p, *prev);
		break;
	case 1: /* Duplicate */
		ddbg("Action dup\n"); /* Both pkts don't trigger a payload action */
		d = __dup_pkt(p);
		__add_pkt(h, d, *prev, p);
		*prev = p;
		break;
	case 2: /* Swap */
		ddbg("Action swap\n");  /* Both pkts don't trigger a payload action */
		tmp_prev = p->next;
		if (__swap_pkt(h, p, *prev, p->next))
			*prev = p;
		else
			*prev = tmp_prev;
		break;
	case 3: /* Swap direction */
		ddbg("Action swap direction\n");
		swap_direction(p);
		*prev = p;
		break;
	}
	if (*prev)
		return (*prev)->next;
	return h->head;
}

static void do_payload_actions(struct m_pkt *p)
{
	if (!p->skip_payload_actions)
		update_do(p);
	else
		ddbg("Skip payload action\n");
}

static size_t __serialize_to_fd(struct pl7m_handle *h, FILE *fd_out,
				size_t max_data_len)
{
	pcap_t *pcap_h;
	pcap_dumper_t *pdumper;
	struct m_pkt *p;
	size_t written;

	/* We must be sure to not write more than max_data_len bytes.
	   PCAP file format:
	   * 24 bytes for global header
	   * packets (with a 16 bytes header)
	*/

	if (max_data_len < 24) {
		derr("Buffer too small: %zu vs 24\n", max_data_len);
		return 0;
	}

	pcap_h = pcap_open_dead(h->datalink, 65535 /* snaplen */);
	if (!pcap_h) {
		derr("Error pcap_open_dead\n");
		return 0;
	}

	pdumper = pcap_dump_fopen(pcap_h, fd_out);
	if (!pcap_h) {
		derr("Error pcap_dump_open");
		pcap_close(pcap_h);
		return 0;
	}
	written = 24;

	p = h->head;
	while (p) {
		if(written + 16 + p->header.caplen >= max_data_len) {
			ddbg("Buffer too small: %zu %u %zu. Skipping packet(s)\n",
			     written, p->header.caplen, max_data_len);
			break;
		}
		pcap_dump((u_char *)pdumper, &p->header, p->raw_data);
		written += 16 + p->header.caplen;
		p = p->next;
		ddbg("dumping pkt\n");
	}

	assert(written <= max_data_len);

	pcap_dump_close(pdumper);
	pcap_close(pcap_h);
	return written;
}

static size_t __serialize(struct pl7m_handle *h, const unsigned char *data,
			  size_t max_data_len)
{
	FILE *f_out;
	size_t data_len = max_data_len;

	f_out = fmemopen((void *)data, max_data_len, "w");
	if (!f_out) {
		derr("Error fmemopen\n");
		return 0;
	}

	data_len = __serialize_to_fd(h, f_out, max_data_len);
	return data_len;
}

static struct pl7m_handle *__deserialize_from_fd(FILE *fd_in)
{
	const u_char *data;
	struct pcap_pkthdr *header;
	struct pl7m_handle *h;
	struct m_pkt *p;
	pcap_t *pcap_h;
	char errbuf[PCAP_ERRBUF_SIZE];
	int rc;
#ifdef PL7M_ENABLE_LOG
	int pkt = 0;
#endif

	ddbg("Deserializing...\n");

	pcap_h = pcap_fopen_offline(fd_in, errbuf);
	if (pcap_h == NULL) {
		derr("Error pcap_open_offline: %s\n", errbuf);
		fclose(fd_in);
		return NULL;
	}

	if (__is_datalink_supported(pcap_datalink(pcap_h)) == 0) {
		derr("Datalink type %d not supported\n", pcap_datalink(pcap_h));
		pcap_close(pcap_h);
		return NULL;
	}

	h = (struct pl7m_handle *)pl7m_calloc(1, sizeof(struct pl7m_handle));
	if (!h) {
		pcap_close(pcap_h);
		return NULL;
	}
	h->datalink = pcap_datalink(pcap_h);

	header = NULL;
	while (pcap_next_ex(pcap_h, &header, &data) > 0) {
		ddbg("Pkt %d\n", ++pkt);

		if (header->caplen > MAX_PKT_LENGTH) {
			derr("Pkt too big %i %i\n", header->caplen, MAX_PKT_LENGTH);
			/* Ignore current pkt, but keep going */
			continue;
		}
		p = (struct m_pkt *)pl7m_calloc(sizeof(struct m_pkt), 1);
		if (!p) {
			__free_m_pkts(h);
			pcap_close(pcap_h);
			return NULL;
		}
		p->raw_data = (unsigned char *)pl7m_malloc(MAX_PKT_LENGTH);
		if (!p->raw_data) {
			pl7m_free(p);
			__free_m_pkts(h);
			pcap_close(pcap_h);
			return NULL;
		}
		assert(header->caplen <= MAX_PKT_LENGTH);
		memcpy(p->raw_data, data, header->caplen);
		p->header = *header;
		p->next = NULL;

		rc = dissect_do(h->datalink, p);
		if (rc != 0) {
			derr("Error dissect_do\n");
			/* Ignore current pkt, but keep going */
			pl7m_free(p->raw_data);
			pl7m_free(p);
			continue;
		}

		__add_pkt(h, p, h->tail, NULL);
		ddbg("Adding pkt (l5_len %d)\n", p->l5_length);
	}

	pcap_close(pcap_h);

	return h;
}

static struct pl7m_handle *__deserialize(const unsigned char *data,
					 size_t data_len)
{
	FILE *f_in;

	if (data_len == 0)
		return NULL;
	f_in = fmemopen((void *)data, data_len, "rw");
	if (!f_in) {
		derr("Error fmemopen\n");
		return NULL;
	}
	return __deserialize_from_fd(f_in);
}

static void __mutate(struct pl7m_handle *h, unsigned int seed)
{
	int r;
	struct m_pkt *p, *prev;

	srand(seed);

	p = h->head;
	prev = NULL;
	while (p) {
		r = rand();
		/* TODO: do these ratios [33%, 33%, 33%] make sense? */
		switch (r % 3) {
		case 0:
			ddbg("Mutate: unchange\n");
			prev = p;
			p = p->next;
			break;
		case 1:
			ddbg("Mutate: packet action\n");
#ifndef PL7M_DISABLE_PACKET_MUTATION
			p = do_pkt_actions(h, p, &prev);
#else
			prev = p;
			p = p->next;
#endif
			break;
		case 2:
			ddbg("Mutate: payload action\n");
#ifndef PL7M_DISABLE_PAYLOAD_MUTATION
			do_payload_actions(p);
#endif
			prev = p;
			p = p->next;
			break;
		}
	}
}

/* Public functions */

size_t pl7m_mutator(uint8_t *data, size_t size, size_t max_size,
		    unsigned int seed)
{
	struct pl7m_handle *h;
	size_t new_size;
	static const uint8_t empty_pcap_file [24] = {
		0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };


	h = __deserialize(data, size);
	if (!h) {
		/* Return an empty, valid pcap file, if possible */
		if (max_size >= 24) {
			memcpy(data, empty_pcap_file, sizeof(empty_pcap_file));
			return sizeof(empty_pcap_file);
		}
		return 0;
	}
	__mutate(h, seed);
	new_size = __serialize(h, data, max_size);
	__free_m_pkts(h);
	return new_size;
}

size_t pl7m_mutator_fd(FILE *fd_in, FILE *fd_out, size_t max_size,
		       unsigned int seed)
{
	struct pl7m_handle *h;
	size_t new_size;
	static const uint8_t empty_pcap_file [24] = {
		0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };


	h = __deserialize_from_fd(fd_in);
	if (!h) {
		/* Return an empty, valid pcap file, if possible */
		if (max_size >= 24) {
			fwrite(empty_pcap_file, sizeof(empty_pcap_file), 1, fd_out);
			return sizeof(empty_pcap_file);
		}
		return 0;
	}
	__mutate(h, seed);
	new_size = __serialize_to_fd(h, fd_out, max_size);
	__free_m_pkts(h);
	return new_size;
}
