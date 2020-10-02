/*
 *
 * dns.h
 *
 * contains some structs and definitions of DNS protocol
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifndef __DNS_H__
#define __DNS_H__

#include "ndpi_includes.h"


// #define DNS_DEBUG 1
// #define DEBUG_DNS_MEMORY



/* extern declaration used here */
void * ndpi_malloc(size_t size);
void * ndpi_calloc(unsigned long count, size_t size);
void * ndpi_realloc(void *ptr, size_t old_size, size_t new_size);
/*
char * ndpi_strdup(const char *s);
void   ndpi_free(void *ptr);
void * ndpi_flow_malloc(size_t size);
void   ndpi_flow_free(void *ptr);
*/

enum DnsResponseCode
{
	/** No error occurred */
	NoError = 0,
	
	/** The server was unable to respond to the query due to a problem with how it was constructed */
	FormatError = 1,
	
	/** The server was unable to respond to the query due to a problem with the server itself */
	ServerFailure = 2,
	
	/** The name specified in the query does not exist in the domain. This code can be used by an authoritative server for a zone
		(since it knows all the objects and subdomains in a domain) or by a caching server that implements negative caching. */
	NameError = 3,
	
	/** The type of query received is not supported by the server */
	NotImplemented = 4,
	
	/** The server refused to process the query, generally for policy reasons and not technical ones. For example, certain types of operations, such as zone transfers, are restricted.*/
	Refused = 5,
	
	/** A name exists when it should not */
	YX_Domain = 6,
	
	/** A resource record set that should not */
	YX_RR_Set = 7,
	
	/** A resource record set that should exists does not. */
	NX_RR_Set = 8,
	
	/** The server receiving the query is not authoritative for the zone specified. */
	NotAuth = 9,
	
	/** A name specified in the message is not within the zone specified in the message */
	NotZone = 10
};

/**
 * An enum for all possible DNS record types
 */
enum DnsType
{
	/** IPv4 address record */
	DNS_TYPE_A= 1,
	/** Name Server record */
	DNS_TYPE_NS= 2,
	/** Obsolete, replaced by MX */
	DNS_TYPE_MD,
	/** Obsolete, replaced by MX */
	DNS_TYPE_MF,
	/** Canonical name record */
	DNS_TYPE_CNAME= 5,
	/** Start of Authority record */
	DNS_TYPE_SOA= 6,
	/** mailbox domain name record */
	DNS_TYPE_MB,
	/** mail group member record */
	DNS_TYPE_MG,
	/** mail rename domain name record */
	DNS_TYPE_MR,
	/** NULL record */
	DNS_TYPE_NULL_R,
	/** well known service description record */
	DNS_TYPE_WKS,
	/** Pointer record */
	DNS_TYPE_PTR= 12,
	/** Host information record */
	DNS_TYPE_HINFO, 
	/** mailbox or mail list information record */
	DNS_TYPE_MINFO,
	/** Mail exchanger record */
	DNS_TYPE_MX= 15,
	/** Text record */
	DNS_TYPE_TXT= 16,
	/** Responsible person record */
	DNS_TYPE_RP,
	/** AFS database record */
	DNS_TYPE_AFSDB,
	/** DNS X25 resource record */
	DNS_TYPE_X25,
	/** Integrated Services Digital Network record */
	DNS_TYPE_ISDN,
	/** Route Through record */
	DNS_TYPE_RT,
	/** network service access point address record */
	DNS_TYPE_NSAP,
	/** network service access point address pointer record */
	DNS_TYPE_NSAP_PTR,
	/** Signature record */
	DNS_TYPE_SIG,
	/** Key record */
	DNS_TYPE_KEY,
	/** Mail Mapping Information record */
	DNS_TYPE_PX,
	/** DNS Geographical Position record */
	DNS_TYPE_GPOS,
	/** IPv6 address record */
	DNS_TYPE_AAAA= 28,
	/**	Location record */
	DNS_TYPE_LOC,
	/** Obsolete record */
	DNS_TYPE_NXT,
	/** DNS Endpoint Identifier record */
	DNS_TYPE_EID,
	/** DNS Nimrod Locator record */
	DNS_TYPE_NIMLOC,
	/** Service locator record */
	DNS_TYPE_SRVS= 33, 
	/** Asynchronous Transfer Mode address record */
	DNS_TYPE_ATMA,
	/** Naming Authority Pointer record */
	DNS_TYPE_NAPTR= 35,
	/** Key eXchanger record */
	DNS_TYPE_KX,
	/** Certificate record */
	DNS_TYPE_CERT,
	/** Obsolete, replaced by AAAA type */
	DNS_TYPE_A6,
	/** Delegation Name record */
	DNS_TYPE_DNAM,
	/** Kitchen sink record */
	DNS_TYPE_SINK,
	/** Option record */
	DNS_TYPE_OPT,
	/** Address Prefix List record */
	DNS_TYPE_APL,
	/** Delegation signer record */
	DNS_TYPE_DS,
	/** SSH Public Key Fingerprint record */
	DNS_TYPE_SSHFP,
	/** IPsec Key record */
	DNS_TYPE_IPSECKEY,
	/** DNSSEC signature record */
	DNS_TYPE_RRSIG,
	/** Next-Secure record */
	DNS_TYPE_NSEC,
	/** DNS Key record */
	DNS_TYPE_DNSKEY,
	/** DHCP identifier record */
	DNS_TYPE_DHCID,
	/** NSEC record version 3 */
	DNS_TYPE_NSEC3,
	/** NSEC3 parameters */
	DNS_TYPE_NSEC3PARAM=51,
	
	/** IXFR parameters */
	DNS_TYPE_IXFR=251,	
	/** AXFR parameters */
	DNS_TYPE_AXFR=252,		
	/** request for Mail Box parameters */
	DNS_TYPE_MAILB=253,		
	/** request for Mail Agent resources */
	DNS_TYPE_MAILA=254,			
	/** All cached records */
	DNS_TYPE_ALL = 255
	
	/* ...32769 ... 65534  */
	
	// 49211
};


/**
 * An enum for all possible DNS classes
 */
enum DnsClass
{
	/** Internet class */
	DNS_CLASS_IN = 1,
	/** CSNET class */
	DNS_CLASS_CS = 2,
	/** Chaos class */
	DNS_CLASS_CH = 3,
	/** Hesiod class */
	DNS_CLASS_HS = 4,
	/** NONE class */
	DNS_CLASS_NONE = 0xFE,
	/** ANY class */
	DNS_CLASS_ANY = 255,
	/** Internet class with QU flag set to True */
	DNS_CLASS_IN_QU = 32769		
};


/**
 * An enum for representing the 4 types of possible DNS records
 */
enum DnsResourceType
{
	/** DNS query record */
	DnsQueryType = 0,
	/** DNS answer record */
	DnsAnswerType = 1,
	/** DNS authority record */
	DnsAuthorityType = 2,
	/** DNS additional record */
	DnsAdditionalType = 3
};

struct ndpi_ip6_addrBIS {
  union {
    u_int8_t   u6_addr8[16];
    u_int16_t  u6_addr16[8];
    u_int32_t  u6_addr32[4];
    u_int64_t  u6_addr64[2];
  } u6_addr;  /* 128-bit IP6 address */
} __attribute__((packed));


typedef struct dnsQuestionSec_t {
	char *		questionName;
	u_int16_t query_type, query_class;	
} dnsQuestionSec;


typedef struct dnsRR_t {
	char* 		rrName;		// string or pointer to name of object
	uint16_t 	rrType;		// resource type(1:A, 5:CNAME, 16:AAAA, ...)
	uint16_t 	rrClass;	// class of the resource record
	uint32_t 	rrTTL;		// cache time to live	
	uint16_t 	rrRDL; 		// resource data length
	
	/* resource Data*/
	union {
		uint32_t addressIP;						// rrType=1
		
		char *NSDName; 							// rrType=2
		
		char *CName;							// rrType=5
		
		struct {								// rrType=6
			char *MName;
			char *RName;
			uint32_t Serial;
			uint32_t Refresh;
			uint32_t Retry;
			uint32_t Expire;
			uint32_t Minimum;
		} SOA;
		
		char *PTRDName;							// rrType=12
		
		struct {								// rrType=13
			uint8_t cpu_len;
			char *cpu;
			uint8_t os_len;
			char *os;
		} HINFO;
		
		struct {								// rrType=15
			uint16_t preference;
			char *exchange;
		} MX;
		
		struct {								// rrType=16
			uint8_t txt_len;
			char *txtData;
		} TXT;	
		
		struct {								// rrType=17
			char *mailbox;
			char *respPerson;
		} RP;
				
		struct {								// rrType=18
			uint16_t subtype;
			char *hostname;
		} AFSDB;
			
		struct ndpi_ip6_addrBIS addressIPv6; 	// rrType=28 
		
		struct {								// rrType=29
			uint8_t  version;
			uint8_t  size;
			uint8_t  hprecs, vprecs;
			uint32_t latit, longit, alt;
		} LOC;
		
		struct {								// rrType=33
			char	*service;
			char	*protocol;
			uint16_t priority;
			uint16_t weight;
			uint16_t port;
			char	*target;			
		} SRVS;
		
		struct {								// rrType=35
			uint16_t order;
			uint16_t preference;
			uint8_t flags_len;
			uint8_t	*flags;
			uint8_t service_len;
			uint8_t	*service;
			uint8_t re_len;
			uint8_t	*regex;
			uint8_t re_replace_len;
			char	*replacement;
		} NAPTR;
		
	} RData;
} dnsRR; // end of dnsRR


typedef struct dnsRRList_t {
	struct dnsRR_t *rrItem;
	struct dnsRRList_t *prevItem, *nextItem; 
} dnsRRList;


/* dns support: function declared and implementated here*/
void free_dns_QSec(struct dnsQuestionSec_t *qs);
void clear_dns_RR_list(struct dnsRRList_t** list, unsigned char bForward);

#endif 