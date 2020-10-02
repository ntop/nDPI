#include "dns_utils.h"

/* ****************************************************** */
char* prot4L(char *ret, size_t len, int protCode) {
	//printf("DBG(prot4L) protCode=%u; buffer=%p, sz=%d\n",protCode, ret, len);
	
    if ( ret ) {
        // look at file: ndpi_typedefs.h for enum
        switch (protCode) {
            case IPPROTO_TCP:
                snprintf(ret,len,"TCP");
                break;
            case IPPROTO_UDP:
                snprintf(ret,len, "UDP");
                break;
            default:
                snprintf(ret,len, "Unknown");
        }
        //printf("DBG(prot4L) protCode=%u -> [%s]\n",protCode, ret);
    }
	return ret;
}

static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
                                 1000000,10000000,100000000,1000000000};
								 
static char* conv2meter(char *ret, size_t len, u_int8_t mis) {
    u_int8_t bs, ex;
    int val;
    if ( ret ) {
        bs= ((mis>>4) & 0xf) % 10;
        ex= (mis & 0x0f) % 10;
        val= bs * poweroften[ex];
        //printf("DBG(conv2m): b: %u, e:%u, tmp:%f -> %u\n", bs, ex, pp, val );
        snprintf(ret,len,"%d.%.2d m",val/100, val%100);
    }
    return ret;
}

static char* conv2Coord(char *ret, size_t len, u_int32_t coord, char letters[2]) {
    int tmpVal, tmpSec, tmpMin, tmpDeg, tmpFrac;
    char letter;
    if ( ret ) {
        tmpVal= coord- ((unsigned)1<<31);
        if ( tmpVal<0 ) {
            letter= letters[1];
            tmpVal=- tmpVal;
        } else {
            letter= letters[0];
        }
        tmpFrac= tmpVal % 1000;
        tmpVal /=1000;
        tmpSec= tmpVal % 60;
        tmpVal /= 60;
        tmpMin= tmpVal % 60;
        tmpVal /= 60;
        tmpDeg= tmpVal;
        
        snprintf(ret,len,"%d %.2d %.2d.%.3d %c",tmpDeg,tmpMin,tmpSec,tmpFrac,letter);
    }
    return ret;
}
static char* conv2Alt(char *ret, size_t len, u_int32_t alt) {
    int altmeters, altfrac;

    char letter;
    if ( ret ) {
        altmeters= (alt>10000000) ? alt-10000000: 10000000-alt;
        altfrac= altmeters % 100;
        altmeters= altmeters/100 * ((alt>10000000)?1:11);
        snprintf(ret,len,"%d.%.2dm",altmeters,altfrac);
    }
    return ret;
}


char* dnsRespCode(char *ret, size_t len, enum DnsResponseCode respCode) {
    //printf("DBG(dnsRespCode) respCode=%u; buffer=%p, sz=%d\n",respCode, ret, len);
	
    if ( ret ) {
        switch(respCode) {
            case NoError: 
                snprintf(ret,len,"OK");
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
                snprintf(ret,len,"ERROR: %02Xh (%u)", respCode, respCode);
                break;
                
            default:
                snprintf(ret,len,"UNKNOWN %02Xh (%u)",respCode, respCode);
        }
    }
	//printf("DBG(dnsRespCode) respCode=%u -> [%s]\n",respCode, ret); 
	return ret;
}


char* dnsClass(char *ret, size_t len, enum DnsClass classIndex) {
    //printf("DBG(dnsClass) classIndex=%u; buffer=%p, sz=%d\n",classIndex, ret, len);
	
    if ( ret ) {
        switch(classIndex) {	
            case DNS_CLASS_IN: 
                snprintf(ret,len,"IN", classIndex);
                break;
            case DNS_CLASS_IN_QU: 
                snprintf(ret,len,"IN_QU", classIndex);
                break;                
            case DNS_CLASS_CH: 
                snprintf(ret,len,"CH", classIndex);
                break;                
            case DNS_CLASS_HS: 
                snprintf(ret,len,"HS", classIndex);
                break;                
            case DNS_CLASS_ANY: 
                snprintf(ret,len,"ANY", classIndex);
                break;                
            default:
                snprintf(ret,len,"UNKNOWN CLASS %02Xh (%u)",classIndex, classIndex);
        }
    }
	//printf("DBG(dnsClass) classIndex=%u -> [%s]\n",classIndex, ret); 
	return ret;
}

char* dnsType(char *ret, size_t len, enum DnsType typeCode) {
	//printf("DBG(dnsType) typeCode=%u; buffer=%p, sz=%d\n",typeCode, ret, len);
	
    if ( ret ) {		
        switch(typeCode) {	
            case DNS_TYPE_A: /** IPv4 address record */
                snprintf(ret,len,"A");
                break;
            case DNS_TYPE_NS: /** Name Server record */
                snprintf(ret,len,"NS");
                break;
            case DNS_TYPE_MD: /** Obsolete, replaced by MX */
                snprintf(ret,len,"MD");
                break;
            case DNS_TYPE_MF: /** Obsolete, replaced by MX */
                snprintf(ret,len,"MF");
                break;
            case DNS_TYPE_CNAME: /** Canonical name record */
                snprintf(ret,len,"CNAME");
                break;
            case DNS_TYPE_SOA: /** Start of Authority record */
                snprintf(ret,len,"SOA");
                break;
            case DNS_TYPE_MB: /** mailbox domain name record */
                snprintf(ret,len,"MB");
                break;
            case DNS_TYPE_MG: /** mail group member record */
                snprintf(ret,len,"MG");
                break;
            case DNS_TYPE_MR: /** mail rename domain name record */
                snprintf(ret,len,"MR");
                break;
            case DNS_TYPE_NULL_R: /** NULL record */
                snprintf(ret,len,"NULL Record");
                break;
            case DNS_TYPE_WKS: /** well known service description record */
                snprintf(ret,len,"WKS");
                break;
            case DNS_TYPE_PTR: /** Pointer record */
                snprintf(ret,len,"PTR");
                break;
            case DNS_TYPE_HINFO: /** Host information record */
                snprintf(ret,len,"HINFO");
                break;
            case DNS_TYPE_MINFO: /** mailbox or mail list information record */
                snprintf(ret,len,"MINFO");
                break;
            case DNS_TYPE_MX: /** Mail exchanger record */
                snprintf(ret,len,"MX");
                break;
            case DNS_TYPE_TXT: /** Text record */
                snprintf(ret,len,"TXT");
                break;
            case DNS_TYPE_RP: /** Responsible person record */
                snprintf(ret,len,"RP");
                break;
            case DNS_TYPE_AFSDB: /** AFS database record */
                snprintf(ret,len,"AFSDB");
                break;
            case DNS_TYPE_X25: /** DNS X25 resource record */
                snprintf(ret,len,"X25");
                break;
            case DNS_TYPE_ISDN: /** Integrated Services Digital Network record */
                snprintf(ret,len,"ISDN");
                break;
            case DNS_TYPE_RT: /** Route Through record */
                snprintf(ret,len,"RT");
                break;
            case DNS_TYPE_NSAP: /** network service access point address record */
                snprintf(ret,len,"NSAP");
                break;
            case DNS_TYPE_NSAP_PTR: /** network service access point address pointer record */
                snprintf(ret,len,"NSAPTR");
                break;
            case DNS_TYPE_SIG: /** Signature record */
                snprintf(ret,len,"SIG");
                break;
            case DNS_TYPE_KEY: /** Key record */
                snprintf(ret,len,"KEY");
                break;
            case DNS_TYPE_PX: /** Mail Mapping Information record */
                snprintf(ret,len,"PX");
                break;
            case DNS_TYPE_GPOS: /** DNS Geographical Position record */
                snprintf(ret,len,"GPOS");
                break;
            case DNS_TYPE_AAAA: /** IPv6 address record */
                snprintf(ret,len,"AAAA");
                break;
            case DNS_TYPE_LOC: /**     Location record */
                snprintf(ret,len,"LOC");
                break;
            case DNS_TYPE_NXT: /** Obsolete record */
                snprintf(ret,len,"NXT");
                break;
            case DNS_TYPE_EID: /** DNS Endpoint Identifier record */
                snprintf(ret,len,"EID");
                break;
            case DNS_TYPE_NIMLOC: /** DNS Nimrod Locator record */
                snprintf(ret,len,"NIMLOC");
                break;
            case DNS_TYPE_SRVS: /** Service locator record */
                snprintf(ret,len,"SRV");
                break;
            case DNS_TYPE_ATMA: /** Asynchronous Transfer Mode address record */
                snprintf(ret,len,"ATMA");
                break;
            case DNS_TYPE_NAPTR: /** Naming Authority Pointer record */
                snprintf(ret,len,"NAPTR");
                break;
            case DNS_TYPE_KX: /** Key eXchanger record */
                snprintf(ret,len,"KX");
                break;
            case DNS_TYPE_CERT: /** Certificate record */
                snprintf(ret,len,"CERT");
                break;
            case DNS_TYPE_A6: /** Obsolete, replaced by AAAA type */
                snprintf(ret,len,"A6");
                break;
            case DNS_TYPE_DNAM: /** Delegation Name record */
                snprintf(ret,len,"DNAM");
                break;
            case DNS_TYPE_SINK: /** Kitchen sink record */
                snprintf(ret,len,"SINK");
                break;
            case DNS_TYPE_OPT: /** Option record */
                snprintf(ret,len,"OPT");
                break;
            case DNS_TYPE_APL: /** Address Prefix List record */
                snprintf(ret,len,"APL");
                break;
            case DNS_TYPE_DS: /** Delegation signer record */
                snprintf(ret,len,"DS");
                break;
            case DNS_TYPE_SSHFP: /** SSH Public Key Fingerprint record */
                snprintf(ret,len,"SSHFP");
                break;
            case DNS_TYPE_IPSECKEY: /** IPsec Key record */
                snprintf(ret,len,"IPSECKEY");
                break;
            case DNS_TYPE_RRSIG: /** DNSSEC signature record */
                snprintf(ret,len,"RRSIG");
                break;
            case DNS_TYPE_NSEC: /** Next-Secure record */
                snprintf(ret,len,"NSEC");
                break;
            case DNS_TYPE_DNSKEY: /** DNS Key record */
                snprintf(ret,len,"DNSKEY");
                break;
            case DNS_TYPE_DHCID: /** DHCP identifier record */
                snprintf(ret,len,"DHCID");
                break;
            case DNS_TYPE_NSEC3: /** NSEC record version 3 */
                snprintf(ret,len,"NSEC3");
                break;
            case DNS_TYPE_NSEC3PARAM: /** NSEC3 parameters */
                snprintf(ret,len,"NSEC3PARAM");
                break;
            case DNS_TYPE_IXFR: /** IXFR */
                snprintf(ret,len,"IXFR");
                break;
            case DNS_TYPE_AXFR: /** AXFR */
                snprintf(ret,len,"AXFR");
                break;
            case DNS_TYPE_MAILB: /** MAILB */
                snprintf(ret,len,"MAILB");
                break;
            case DNS_TYPE_MAILA: /** MAILA */
                snprintf(ret,len,"MAILA");
                break;				
            case DNS_TYPE_ALL: /** All cached records */
                snprintf(ret,len,"ALL");
                break;
            
            default:
                snprintf(ret,len,"UNKNOWN %02Xh (%u)",typeCode,typeCode);
        }
	}
	//printf("DBG(dnsType) typeCode=%u -> [%s]\n",typeCode, ret); 
	return ret;
}

char *dnsRData(char *ret, size_t len, struct dnsRR_t *rr ) {
    char sTemp1[25]={0},sTemp2[25]={0},sTemp3[25]={0},sTemp4[25]={0},sTemp5[25]={0},sTemp6[25]={0};

	//printf("DBG(dnsRData) rr=%p; buffer=%p, sz=%d\n",rr, ret, len);
    
    if ( ret && rr ) {
        //printf("DBG(dnsRData) rr type = %02Xh (%u)\n",rr->rrType,rr->rrType);
        switch(rr->rrType) {
            case DNS_TYPE_A:
                //printRawData((uint8_t*)&rr->RData.addressIP,4);
                inet_ntop(AF_INET, &rr->RData.addressIP, ret,len);			
                //printf("DBG(dnsRData) rrType= %u - (%d) %s\n",rr->rrType, strlen(ret),ret);
                break;
                
            case DNS_TYPE_NS:
                snprintf(ret,len, "%s", rr->RData.NSDName);
                break;			
                
            case DNS_TYPE_CNAME:
                snprintf(ret,len, "%s", rr->RData.CName);
                break;
                
            case DNS_TYPE_SOA:
                // Admin: azuredns-hostmaster.microsoft.com, Primary Server: ns1-03.azure-dns.com, Default TTL: 300, Expire: 2419200, Refresh: 3600, Retry: 300, Serial: 1	
                snprintf(ret,len, "Admin: %s, Primary Server: %s, Default TTL: %u, Expire: %u, Refresh: %u, Retry: %u, Serial: %u", 
                    rr->RData.SOA.RName,rr->RData.SOA.MName,rr->RData.SOA.Minimum,rr->RData.SOA.Expire,rr->RData.SOA.Refresh,rr->RData.SOA.Retry,rr->RData.SOA.Serial);
                break;
            
            case DNS_TYPE_PTR:
                snprintf(ret,len, "%s", rr->RData.PTRDName);
                break;

			case DNS_TYPE_HINFO:
                snprintf(ret,len, "CPU: (%d) %s, OS: (%d) %s", rr->RData.HINFO.cpu_len, rr->RData.HINFO.cpu, rr->RData.HINFO.os_len, rr->RData.HINFO.os);
                break;
				
            case DNS_TYPE_MX:
                snprintf(ret,len, "(priority: %d) %s", rr->RData.MX.preference, rr->RData.MX.exchange);
                break;
            
            case DNS_TYPE_TXT:
                snprintf(ret,len, "(%u) %s", rr->RData.TXT.txt_len,rr->RData.TXT.txtData);
                break;

            case DNS_TYPE_RP:
                //Master file format: <owner> <ttl> <class> RP <mbox-dname> <txt-dname>
                snprintf(ret,len, "mailbox: %s, TXT: %s", rr->RData.RP.mailbox,rr->RData.RP.respPerson);
                break;

            case DNS_TYPE_AFSDB:
                //Master file format: <owner> <ttl> <class> AFSDB <subtype> <hostname>
                snprintf(ret,len, "subtype: %d, hostname: %s", rr->RData.AFSDB.subtype, rr->RData.AFSDB.hostname);
                break;

            case DNS_TYPE_AAAA:	
                //printRawData((uint8_t*)&rr->RData.addressIP,16);
                inet_ntop(AF_INET6, (struct sockaddr_in6 *)&rr->RData.addressIPv6, ret,len);
                /* For consistency across platforms replace :0: with :: */
                ndpi_patchIPv6Address(ret);
                break;

            case DNS_TYPE_LOC:
                /*Master file format: <owner> <ttl> <class> LOC ( d1 [m1 [s1]] {"N"|"S"} d2 [m2 [s2]]
                               {"E"|"W"} alt["m"] [siz["m"] [hp["m"]
                               [vp["m"]]]] )*/
                snprintf(ret,len, "%s %s alt: %s siz: %s hp: %s vp: %s ", 
                    conv2Coord(sTemp1,sizeof(sTemp1),rr->RData.LOC.latit,"NS"),
                    conv2Coord(sTemp2,sizeof(sTemp2),rr->RData.LOC.longit,"EW"),
                    conv2Alt(sTemp3,sizeof(sTemp3),rr->RData.LOC.alt),
                    conv2meter(sTemp4, sizeof(sTemp4),rr->RData.LOC.size), 
                    conv2meter(sTemp5, sizeof(sTemp5),rr->RData.LOC.hprecs),
                    conv2meter(sTemp6, sizeof(sTemp6),rr->RData.LOC.vprecs) );
                break;

            case DNS_TYPE_SRVS:
                /* Master file format: _Service._Proto.Name TTL Class SRV Priority Weight Port Target */
                snprintf(ret,len, "(service:%s, protocol: %s) priority:%d, weight:%d, port:%d, target: %s", 
                    rr->RData.SRVS.service,rr->RData.SRVS.protocol,
                    rr->RData.SRVS.priority,rr->RData.SRVS.weight,
                    rr->RData.SRVS.port,rr->RData.SRVS.target);
                break;

            case DNS_TYPE_NAPTR:
                snprintf(ret,len, "order:%d, preferences:%d, flags: (%d) %.*s, service: (%d) %.*s, regex: (%d) %.*s, replacement: (%d) %.*s", 
                    rr->RData.NAPTR.order,rr->RData.NAPTR.preference,
                    rr->RData.NAPTR.flags_len,rr->RData.NAPTR.flags_len,rr->RData.NAPTR.flags,
                    rr->RData.NAPTR.service_len,rr->RData.NAPTR.service_len,rr->RData.NAPTR.service,
                    rr->RData.NAPTR.re_len,rr->RData.NAPTR.re_len,rr->RData.NAPTR.regex,
                    rr->RData.NAPTR.re_replace_len,rr->RData.NAPTR.re_replace_len,rr->RData.NAPTR.replacement);
                break;

            case DNS_TYPE_IXFR:
            case DNS_TYPE_AXFR:
                //snprintf(ret,len, "%s", rr->RData.txtData);
                break;

			default:
                snprintf(ret,len,"UNKNOWN %02Xh (%u)",rr->rrType,rr->rrType);
        }
    }
	//printf("DBG(dnsRData) line=[%s]\n", ret);

	return ret;
}
