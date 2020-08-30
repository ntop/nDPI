#include "dns_utils.h"

/* ****************************************************** */
char* prot4L(char *ret, int protCode) {
	char retInt[10]={0};
	//printf("DBG(prot4L) methodCode=%u\n",methodCode);
	
	// look at file: ndpi_typedefs.h for enum
	switch (protCode) {
			break;
		case IPPROTO_UDP:
			snprintf(retInt,sizeof(retInt), "UDP");
		case IPPROTO_TCP:
			snprintf(retInt,sizeof(retInt),"TCP");
			break;
		default:
			snprintf(retInt,sizeof(retInt), "Unknown");
	}
	//printf("DBG(httpMethod) methodCode=%u - %s\n",methodCode, retInt);
	if (ret!=NULL) {
		sprintf(ret,"%s",retInt);
	}
	return ret;
}

char* dnsRespCode(char *ret, enum DnsResponseCode respCode) {
	char retInt[40]={0};

	switch(respCode) {	
		case NoError: 
			snprintf(retInt,sizeof(retInt),"OK");
			break;
		case FormatError: 
		case ServerFailure: 
		case NameError: 
		case NotImplemented: 
		case Refused: 
		case YX_Domain: 
		case YX_RR_Set: 
		case NotAuth: 
		case NotZone: 
			snprintf(retInt,sizeof(retInt),"ERROR: %02Xh (%u)", respCode, respCode);
			break;
			
		default:
			snprintf(retInt,sizeof(retInt),"UNKNOWN %02Xh (%u)",respCode, respCode);
	}
	
	//printf("DBG(dnsClass) classIndex=%u - %s\n",classIndex, retInt);
	if (ret!=NULL) {
		sprintf(ret,"%s",retInt);
	}
	return ret;
}


char* dnsClass(char *ret, enum DnsClass classIndex) {
	char retInt[10]={0};

	switch(classIndex) {	
		case DNS_CLASS_IN: 
			snprintf(retInt,sizeof(retInt),"IN");
			break;
		case DNS_CLASS_IN_QU: 
			snprintf(retInt,sizeof(retInt),"IN_QU");
			break;
		case DNS_CLASS_CH: 
			snprintf(retInt,sizeof(retInt),"CH");
			break;
		case DNS_CLASS_HS: 
			snprintf(retInt,sizeof(retInt),"HS");
			break;
		case DNS_CLASS_ANY: 
			snprintf(retInt,sizeof(retInt),"ANY");
			break;	
			
		default:
			snprintf(retInt,sizeof(retInt),"UNKNOWN (%u)",classIndex);
	}
	
	//printf("DBG(dnsClass) classIndex=%u - %s\n",classIndex, retInt);
	if (ret!=NULL) {
		sprintf(ret,"%s",retInt);
	}
	return ret;
}

char* dnsType(char *ret, enum DnsType typeCode) {
	char retInt[20]={0};
		
	switch(typeCode) {	
		case DNS_TYPE_A: /** IPv4 address record */
			snprintf(retInt,sizeof(retInt),"A");
			break;
		case DNS_TYPE_NS: /** Name Server record */
			snprintf(retInt,sizeof(retInt),"NS");
			break;
		case DNS_TYPE_MD: /** Obsolete, replaced by MX */
			snprintf(retInt,sizeof(retInt),"MD");
			break;
		case DNS_TYPE_MF: /** Obsolete, replaced by MX */
			snprintf(retInt,sizeof(retInt),"MF");
			break;
		case DNS_TYPE_CNAME: /** Canonical name record */
			snprintf(retInt,sizeof(retInt),"CNAME");
			break;
		case DNS_TYPE_SOA: /** Start of Authority record */
			snprintf(retInt,sizeof(retInt),"SOA");
			break;
		case DNS_TYPE_MB: /** mailbox domain name record */
			snprintf(retInt,sizeof(retInt),"MB");
			break;
		case DNS_TYPE_MG: /** mail group member record */
			snprintf(retInt,sizeof(retInt),"MG");
			break;
		case DNS_TYPE_MR: /** mail rename domain name record */
			snprintf(retInt,sizeof(retInt),"MR");
			break;
		case DNS_TYPE_NULL_R: /** NULL record */
			snprintf(retInt,sizeof(retInt),"NULL Record");
			break;
		case DNS_TYPE_WKS: /** well known service description record */
			snprintf(retInt,sizeof(retInt),"WKS");
			break;
		case DNS_TYPE_PTR: /** Pointer record */
			snprintf(retInt,sizeof(retInt),"PTR");
			break;
		case DNS_TYPE_HINFO: /** Host information record */
			snprintf(retInt,sizeof(retInt),"H INFO");
			break;
		case DNS_TYPE_MINFO: /** mailbox or mail list information record */
			snprintf(retInt,sizeof(retInt),"M INFO");
			break;
		case DNS_TYPE_MX: /** Mail exchanger record */
			snprintf(retInt,sizeof(retInt),"MX");
			break;
		case DNS_TYPE_TXT: /** Text record */
			snprintf(retInt,sizeof(retInt),"TXT");
			break;
		case DNS_TYPE_RP: /** Responsible person record */
			snprintf(retInt,sizeof(retInt),"RP");
			break;
		case DNS_TYPE_AFSDB: /** AFS database record */
			snprintf(retInt,sizeof(retInt),"AFS");
			break;
		case DNS_TYPE_X25: /** DNS X25 resource record */
			snprintf(retInt,sizeof(retInt),"X25");
			break;
		case DNS_TYPE_ISDN: /** Integrated Services Digital Network record */
			snprintf(retInt,sizeof(retInt),"ISDN");
			break;
		case DNS_TYPE_RT: /** Route Through record */
			snprintf(retInt,sizeof(retInt),"RT");
			break;
		case DNS_TYPE_NSAP: /** network service access point address record */
			snprintf(retInt,sizeof(retInt),"NSAP");
			break;
		case DNS_TYPE_NSAP_PTR: /** network service access point address pointer record */
			snprintf(retInt,sizeof(retInt),"NSAPTR");
			break;
		case DNS_TYPE_SIG: /** Signature record */
			snprintf(retInt,sizeof(retInt),"SIG");
			break;
		case DNS_TYPE_KEY: /** Key record */
			snprintf(retInt,sizeof(retInt),"KEY");
			break;
		case DNS_TYPE_PX: /** Mail Mapping Information record */
			snprintf(retInt,sizeof(retInt),"PX");
			break;
		case DNS_TYPE_GPOS: /** DNS Geographical Position record */
			snprintf(retInt,sizeof(retInt),"GPOS");
			break;
		case DNS_TYPE_AAAA: /** IPv6 address record */
			snprintf(retInt,sizeof(retInt),"AAAA");
			break;
		case DNS_TYPE_LOC: /**     Location record */
			snprintf(retInt,sizeof(retInt),"LOC");
			break;
		case DNS_TYPE_NXT: /** Obsolete record */
			snprintf(retInt,sizeof(retInt),"NXT");
			break;
		case DNS_TYPE_EID: /** DNS Endpoint Identifier record */
			snprintf(retInt,sizeof(retInt),"EID");
			break;
		case DNS_TYPE_NIMLOC: /** DNS Nimrod Locator record */
			snprintf(retInt,sizeof(retInt),"NIMLOC");
			break;
		case DNS_TYPE_SRV: /** Service locator record */
			snprintf(retInt,sizeof(retInt),"SRV");
			break;
		case DNS_TYPE_ATMA: /** Asynchronous Transfer Mode address record */
			snprintf(retInt,sizeof(retInt),"ATMA");
			break;
		case DNS_TYPE_NAPTR: /** Naming Authority Pointer record */
			snprintf(retInt,sizeof(retInt),"NAPTR");
			break;
		case DNS_TYPE_KX: /** Key eXchanger record */
			snprintf(retInt,sizeof(retInt),"KX");
			break;
		case DNS_TYPE_CERT: /** Certificate record */
			snprintf(retInt,sizeof(retInt),"CERT");
			break;
		case DNS_TYPE_A6: /** Obsolete, replaced by AAAA type */
			snprintf(retInt,sizeof(retInt),"A6");
			break;
		case DNS_TYPE_DNAM: /** Delegation Name record */
			snprintf(retInt,sizeof(retInt),"DNAM");
			break;
		case DNS_TYPE_SINK: /** Kitchen sink record */
			snprintf(retInt,sizeof(retInt),"SINK");
			break;
		case DNS_TYPE_OPT: /** Option record */
			snprintf(retInt,sizeof(retInt),"OPT");
			break;
		case DNS_TYPE_APL: /** Address Prefix List record */
			snprintf(retInt,sizeof(retInt),"APL");
			break;
		case DNS_TYPE_DS: /** Delegation signer record */
			snprintf(retInt,sizeof(retInt),"DS");
			break;
		case DNS_TYPE_SSHFP: /** SSH Public Key Fingerprint record */
			snprintf(retInt,sizeof(retInt),"SSHFP");
			break;
		case DNS_TYPE_IPSECKEY: /** IPsec Key record */
			snprintf(retInt,sizeof(retInt),"IPSECKEY");
			break;
		case DNS_TYPE_RRSIG: /** DNSSEC signature record */
			snprintf(retInt,sizeof(retInt),"RRSIG");
			break;
		case DNS_TYPE_NSEC: /** Next-Secure record */
			snprintf(retInt,sizeof(retInt),"NSEC");
			break;
		case DNS_TYPE_DNSKEY: /** DNS Key record */
			snprintf(retInt,sizeof(retInt),"DNSKEY");
			break;
		case DNS_TYPE_DHCID: /** DHCP identifier record */
			snprintf(retInt,sizeof(retInt),"DHCID");
			break;
		case DNS_TYPE_NSEC3: /** NSEC record version 3 */
			snprintf(retInt,sizeof(retInt),"NSEC3");
			break;
		case DNS_TYPE_NSEC3PARAM: /** NSEC3 parameters */
			snprintf(retInt,sizeof(retInt),"NSEC3PARAM");
			break;
		case DNS_TYPE_ALL: /** All cached records */
			snprintf(retInt,sizeof(retInt),"ALL");
			break;
		
		default:
			snprintf(retInt,sizeof(retInt),"UNKNOWN (%u)",typeCode);
	}
	
	//printf("DBG(dnsType) typeCode=%u - %s\n",typeCode, retInt);
	if (ret!=NULL) {
        sprintf(ret,"%s",retInt);
	}
	return ret;
}

char* dnsRData(char *ret, struct dnsRR_t *rr ) {
	char line[1024]={0};
	
	//printf("DBG(dnsRData): %p, %p \n",ret,rr);
	
	switch(rr->rrType) {
		case DNS_TYPE_A:
			//printRawData((uint8_t*)&rr->RData.addressIP,4);
			inet_ntop(AF_INET, &rr->RData.addressIP, line, sizeof(line));			
			//printf("DBG(dnsRData) rrType= %u - (%d) %s\n",rr->rrType, strlen(line),line);
			break;
			
		case DNS_TYPE_NS:
			snprintf(line,sizeof(line), "%s", rr->RData.NSDName);
			break;			
			
		case DNS_TYPE_CNAME:
			snprintf(line,sizeof(line), "%s", rr->RData.CName);
			break;
			
		case DNS_TYPE_SOA:
			// Admin: azuredns-hostmaster.microsoft.com, Primary Server: ns1-03.azure-dns.com, Default TTL: 300, Expire: 2419200, Refresh: 3600, Retry: 300, Serial: 1	
			snprintf(line,sizeof(line), "Admin: %s, Primary Server: %s, Default TTL: %u, Expire: %u, Refresh: %u, Retry: %u, Serial: %u", 
				rr->RData.SOA.RName,rr->RData.SOA.MName,rr->RData.SOA.Minimum,rr->RData.SOA.Expire,rr->RData.SOA.Refresh,rr->RData.SOA.Retry,rr->RData.SOA.Serial);
			break;
		
		case DNS_TYPE_PTR:
			snprintf(line,sizeof(line), "%s", rr->RData.PTRDName);
			break;

		case DNS_TYPE_MX:
			snprintf(line,sizeof(line), "(priority: %d) %s", rr->RData.MX.preference, rr->RData.MX.exchange);
			break;
		
		case DNS_TYPE_TXT:
			snprintf(line,sizeof(line), "%s", rr->RData.txtData);
			break;
			
		case DNS_TYPE_AAAA:	
			//printRawData((uint8_t*)&rr->RData.addressIP,16);
			inet_ntop(AF_INET6, (struct sockaddr_in6 *)&rr->RData.addressIPv6, line, sizeof(line));
			/* For consistency across platforms replace :0: with :: */
			ndpi_patchIPv6Address(line);
			break;
	}
	// printf("DBG(dnsRData): line=[%s]\n", line);
	if (ret!=NULL) {
        sprintf(ret,"%s",line);
	}
	return ret;
}

