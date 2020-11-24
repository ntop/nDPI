/*
 * dns.c
 *
 * Copyright (C) 2012-20 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdbool.h>
 
#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DNS


#include "ndpi_api.h"

#include "dns.h"

#define FLAGS_MASK 0x8000


static void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow);

/* ****************************************************** */

static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
                                 1000000,10000000,100000000,1000000000};

static char* conv2meter(char *ret, size_t len, u_int8_t mis) {
    u_int8_t bs, ex;
    if ( ret ) {
        bs= ((mis>>4) & 0xf) % 10;
        ex= (mis & 0x0f) % 10;
        int val= bs * poweroften[ex];
        //printf("DBG(conv2m): b: %u, e:%u, tmp:%f -> %u\n", bs, ex, pp, val );
        snprintf(ret,len,"%d.%.2d m",val/100, val%100);
    }
    return ret;
}

static char* conv2Coord(char *ret, size_t len, u_int32_t coord, char letters[2]) {    
    if ( ret ) {
        char letter;
        int tmpVal, tmpSec, tmpMin, tmpDeg, tmpFrac;
        tmpVal= coord- ((unsigned)1<<31);
        if ( tmpVal<0 ) {
            letter= letters[1];
            tmpVal= -tmpVal;
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
    
    if ( ret ) {
        int altmeters, altfrac;
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
                snprintf(ret,len,"IN");
                break;
            case DNS_CLASS_IN_QU: 
                snprintf(ret,len,"IN_QU");
                break;                
            case DNS_CLASS_CH: 
                snprintf(ret,len,"CH");
                break;                
            case DNS_CLASS_HS: 
                snprintf(ret,len,"HS");
                break;                
            case DNS_CLASS_ANY: 
                snprintf(ret,len,"ANY");
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
	
    if ( ret && len>0 ) {	
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
    
	//printf("DBG(dnsRData) rr=%p; buffer=%p, sz=%d\n",rr, ret, len);
    
    if ( ret && rr ) {
        char sTemp1[25]={0},sTemp2[25]={0},sTemp3[25]={0},sTemp4[25]={0},sTemp5[25]={0},sTemp6[25]={0};

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

/* *********************************************** */

static void ndpi_check_dns_type(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				u_int16_t dns_type) {
  /* https://en.wikipedia.org/wiki/List_of_DNS_record_types */

  switch(dns_type) {
    /* Obsolete record types */
  case 3:	// DNS_TYPE_MD
  case 4:	// DNS_TYPE_MF
  case 254:	// DNS_TYPE_MAILA
  case 7:	// DNS_TYPE_MB
  case 8:	// DNS_TYPE_MG
  case 9:	// DNS_TYPE_MR
  case 14:	// DNS_TYPE_MINFO
  case 253:	// DNS_TYPE_MAILB
  case 11:	// DNS_TYPE_WKS
  case 33:	// DNS_TYPE_SRVS
  case 10:	// DNS_TYPE_NULL_R
  case 38:	// DNS_TYPE_A6
  case 30:	// DNS_TYPE_NXT
  case 25:	// DNS_TYPE_KEY
  case 24:	// DNS_TYPE_SIG
  case 13:	// DNS_TYPE_HINFO
  case 17:	// DNS_TYPE_RP
  case 19:	// DNS_TYPE_X25
  case 20:	// DNS_TYPE_ISDN
  case 21:	// DNS_TYPE_RT
  case 22:	// DNS_TYPE_NSAP
  case 23:	// DNS_TYPE_NSAP_PTR
  case 26:	// DNS_TYPE_PX
  case 31:	// DNS_TYPE_EID
  case 32:	// DNS_TYPE_NIMLOC
  case 34:	// DNS_TYPE_ATMA
  case 42:	// DNS_TYPE_APL
  case 40:	// DNS_TYPE_SINK
  case 27:	// DNS_TYPE_GPOS
  case 100:	// 
  case 101:	// 
  case 102:	// 
  case 103:	// 
  case 99:	// 
  case 56:	// 
  case 57:	// 
  case 58:	// 
  case 104:	// 
  case 105:	// 
  case 106:	// 
  case 107:	// 
  case 259:	// 
    NDPI_SET_BIT(flow->risk, NDPI_DNS_SUSPICIOUS_TRAFFIC);
    break;
  }
}

/* *********************************************** */

static u_int16_t checkPort(u_int16_t port) {
  switch(port) {
  case DNS_PORT:
    return(NDPI_PROTOCOL_DNS);
    break;
  case LLMNR_PORT:
    return(NDPI_PROTOCOL_LLMNR);
    break;
  case MDNS_PORT:
    return(NDPI_PROTOCOL_MDNS);
    break;
  }

  return(0);
}

/* *********************************************** */

static u_int16_t checkDNSSubprotocol(u_int16_t sport, u_int16_t dport) {
  u_int16_t rc = checkPort(sport);

  if(rc == 0)
    return(checkPort(dport));
  else
    return(rc);
}

/* *********************************************** */

static u_int16_t get16(int *i, const u_int8_t *payload) {
  u_int16_t v = *(u_int16_t*)&payload[*i];

  (*i) += 2;

  return(ntohs(v));
}

static u_int32_t get32(int *i, const u_int8_t *payload) {
  uint32_t v = *(uint32_t*)&payload[*i];

  (*i) += 4;

  return(ntohl(v));
}

/**
 * return NULL for error
 * */
static struct dnsQSList_t *add_QS_elem_to_list(struct dnsQSList_t *currList, struct dnsQuestionSec_t *newItem) {
	
	DBGTRACER("current dnsQS list: %p, item: %p",currList,newItem)
	struct dnsQSList_t *retList= ndpi_calloc(1, sizeof(struct dnsQSList_t));
	DBGPOINTER( "allocated %lu bytes of memory for pointer: %p.", sizeof(struct dnsQSList_t), retList) 

	if ( retList ) {	
		retList->qsItem= newItem;
		retList->nextItem= NULL;
		
		if ( currList ) {
			currList->nextItem= retList;
			retList->prevItem= currList;
		} 
		else {
			retList->prevItem= NULL;
		}
		DBGTRACER("return dnsQS list: %p",retList)
		return retList;
	} else {
		ERRLOG("allocating memory for new dnsQS list pointer")
	}
	return NULL;
}

/**
 * return NULL, for error
 * */
static struct dnsRRList_t *add_RR_elem_to_list(struct dnsRRList_t *currList, struct dnsRR_t *newItem) {
	
	DBGTRACER("current dnsRR list: %p, item: %p",currList,newItem)

	struct dnsRRList_t *retList= ndpi_calloc(1, sizeof(struct dnsRRList_t));
	DBGPOINTER("allocated %lu bytes of memory for pointer(dnsRRList_t): %p.", sizeof(struct dnsRRList_t), retList ) 
	if ( retList ) {
		retList->rrItem= newItem;
		retList->nextItem= NULL;
		
		if ( currList ) {
			currList->nextItem= retList;
			retList->prevItem= currList;
		} 
		else {
			retList->prevItem= NULL;
		}
		DBGTRACER("return dnsRR list: %p",retList)
	} else {
		ERRLOG("allocating memory for new dnsRR list pointer")
	}
		return retList;
	}	

static void free_dns_QSec(struct dnsQuestionSec_t *qs) {
	if (qs) {
		DBGTRACER("dnsQS item=%p, questionName=%p \n",qs,qs->questionName)
		if (qs->questionName) ndpi_free(qs->questionName);
		ndpi_free(qs);
	}
}

static void free_dns_RR(struct dnsRR_t *rr) {
	if (rr) {
		DBGTRACER("dnsRR item=%p, rrName=%p, rrType=%d ",rr,rr->rrName,rr->rrType)
		if (rr->rrName) ndpi_free(rr->rrName);
		
		switch(rr->rrType) {
			case DNS_TYPE_NS:
				DBGTRACER("rr=%p, RData.NSDName=%p",rr,rr->RData.NSDName)
				if (rr->RData.NSDName) ndpi_free(rr->RData.NSDName);
				break;
			case DNS_TYPE_CNAME:
				DBGTRACER("rr=%p, RData.CName=%p",rr,rr->RData.CName)
				if (rr->RData.CName) ndpi_free(rr->RData.CName);		
				break;
			case DNS_TYPE_SOA:
				DBGTRACER("rr=%p, RData.SOA.MName=%p",rr,rr->RData.SOA.MName)
				if (rr->RData.SOA.MName) ndpi_free(rr->RData.SOA.MName);
				DBGTRACER("rr=%p, RData.SOA.RName=%p",rr,rr->RData.SOA.RName)
				if (rr->RData.SOA.RName) ndpi_free(rr->RData.SOA.RName);
				break;		
			case DNS_TYPE_PTR:
				DBGTRACER("rr=%p, RData.PTRDName=%p",rr,rr->RData.PTRDName)
				if (rr->RData.PTRDName) ndpi_free(rr->RData.PTRDName);		
				break;		
			case DNS_TYPE_HINFO:
				DBGTRACER("rr=%p, HINFO.cpu=%p",rr,rr->RData.HINFO.cpu)
				if (rr->RData.HINFO.cpu) ndpi_free(rr->RData.HINFO.cpu);		
				DBGTRACER("rr=%p, RData.HINFO.os=%p",rr,rr->RData.HINFO.os)
				if (rr->RData.HINFO.os) ndpi_free(rr->RData.HINFO.os);		
				break;
			case DNS_TYPE_MX:
				DBGTRACER("rr=%p, RData.MX.exchange=%p",rr,rr->RData.MX.exchange)
				if (rr->RData.MX.exchange) ndpi_free(rr->RData.MX.exchange);
				break;		
			case DNS_TYPE_TXT:
				DBGTRACER("rr=%p, RData.TXT.txtData=%p.",rr,rr->RData.TXT.txtData)
				if (rr->RData.TXT.txtData) ndpi_free(rr->RData.TXT.txtData);		
				break;
			case DNS_TYPE_RP:
				DBGTRACER("rr=%p, RData.RP.mailbox=%p.",rr,rr->RData.RP.mailbox)
				if (rr->RData.RP.mailbox) ndpi_free(rr->RData.RP.mailbox);
				DBGTRACER("rr=%p, RData.RP.respPerson=%p.",rr,rr->RData.RP.respPerson)
				if (rr->RData.RP.respPerson) ndpi_free(rr->RData.RP.respPerson);
				break;
			case DNS_TYPE_AFSDB:
				DBGTRACER("rr=%p, RData.AFSDB.hostname=%p.",rr,rr->RData.AFSDB.hostname)
				if (rr->RData.AFSDB.hostname) ndpi_free(rr->RData.AFSDB.hostname);		
				break;	
			case DNS_TYPE_LOC:
				break;
			case DNS_TYPE_SRVS:
				DBGTRACER("rr=%p, RData.SRVS.service=%p.",rr,rr->RData.SRVS.service)
				if (rr->RData.SRVS.service) ndpi_free(rr->RData.SRVS.service);
				DBGTRACER("rr=%p, RData.SRVS.protocol=%p.",rr,rr->RData.SRVS.protocol)
				if (rr->RData.SRVS.protocol) ndpi_free(rr->RData.SRVS.protocol);
				DBGTRACER("rr=%p, RData.SRVS.target=%p.",rr,rr->RData.SRVS.target)
				if (rr->RData.SRVS.target) ndpi_free(rr->RData.SRVS.target);
				break;
			case DNS_TYPE_NAPTR:
				DBGTRACER("rr=%p, RData.NAPTR.flags=%p.",rr,rr->RData.NAPTR.flags)
				if (rr->RData.NAPTR.flags) ndpi_free(rr->RData.NAPTR.flags);
				DBGTRACER("rr=%p, RData.NAPTR.service=%p.",rr,rr->RData.NAPTR.service)
				if (rr->RData.NAPTR.service) ndpi_free(rr->RData.NAPTR.service);
				DBGTRACER("rr=%p, RData.NAPTR.regex=%p.",rr,rr->RData.NAPTR.regex)
				if (rr->RData.NAPTR.regex) ndpi_free(rr->RData.NAPTR.regex);
				DBGTRACER("rr=%p, RData.NAPTR.replacement=%p.",rr,rr->RData.NAPTR.replacement)
				if (rr->RData.NAPTR.replacement) ndpi_free(rr->RData.NAPTR.replacement);
				break;
				
				//TODO: free all other implemented fields/structures
		};	
		ndpi_free(rr);
	}
}

void clear_dns_QS_list(struct dnsQSList_t **qsList, unsigned char bForward) {
	struct dnsQSList_t *currList=*qsList;
	while (currList!=NULL) {
		DBGTRACER("currList=%p, item=%p",currList,currList->qsItem)
		free_dns_QSec(currList->qsItem);
		struct dnsQSList_t* tmp= (bForward) ? currList->nextItem :  currList->prevItem;
		DBGTRACER("delete item: %p",currList)
		ndpi_free( currList );
		currList= tmp;		
	}
	*qsList=NULL;
}

void clear_dns_RR_list(struct dnsRRList_t **rrList, unsigned char bForward) {	
	DBGTRACER("*rrList=%p, bForward=%d",*rrList,bForward)
	struct dnsRRList_t *currList=*rrList;
	while (currList!=NULL) {
		DBGTRACER("currList=%p, item=%p",currList,currList->rrItem)
		free_dns_RR(currList->rrItem);
		struct dnsRRList_t* tmp= (bForward) ? currList->nextItem :  currList->prevItem;
		DBGTRACER("delete item: %p",currList)
		ndpi_free( currList );
		currList= tmp;		
	}
	*rrList=NULL;
}

void clear_all_dns_list(struct ndpi_flow_struct *flow) {
	if ( flow->protos.dns.dnsQueriesList!=NULL ) clear_dns_QS_list(&flow->protos.dns.dnsQueriesList,1);
	if ( flow->protos.dns.dnsAnswerRRList!=NULL ) clear_dns_RR_list(&flow->protos.dns.dnsAnswerRRList,1);
	if ( flow->protos.dns.dnsAuthorityRRList!=NULL ) clear_dns_RR_list(&flow->protos.dns.dnsAuthorityRRList,1);
	if ( flow->protos.dns.dnsAdditionalRRList!=NULL ) clear_dns_RR_list(&flow->protos.dns.dnsAdditionalRRList,1);
}
/* *********************************************** */

/*
  get the DNS name length, 
  using the DNS Name Notation and Message Compression Technique
  so:
	if there is a pointer to other location of packet (c0), 
	jumps there and continue with count.
	return the real length of dns name, without change the pointer  
*/  
int getNameLength(u_int i, const u_int8_t *payload, u_int payloadLen) { 
  int retLen;
  
  DBGTRACER("off/tot => %d/%d",i,payloadLen)

  if(i >= payloadLen) {
    /* Error / Bad packet */
    return(-1);
  } else if(payload[i] == 0x00)
    return(0);
  else if ((payload[i] & 0xc0) != 0) {
	if(i+1 >= payloadLen) {
	  /* Error / Bad packet */
      return(-1);
	} 
	u_int16_t noff = payload[i+1];	// jump to new position
	 DBGTRACER("new off(LO)=%d",noff)
	 DBGTRACER("new off(HI)=%d",((payload[i] & 0x3f)<<8))

	noff += ((payload[i] & 0x3f)<<8);
	 DBGTRACER("jump to pos=%d",noff)
    retLen=getNameLength(noff, payload, payloadLen);
	 DBGTRACER("returned from c0 jump len=%d",retLen)
	return (retLen);
  } else {
    u_int16_t len= payload[i]+1;	// word length and dot or termination char
    u_int16_t off = len; // new offset 
	 DBGTRACER("curr len=%d",len)

	  retLen=getNameLength(i+off, payload, payloadLen);
	  if (retLen<0) return -2;

	  DBGTRACER("returned len=%d",retLen)
	  return (len + retLen);	  
  }
}

/* *********************************************** */

/*
  allowed chars for dns names A-Z 0-9 _ -
  Perl script for generation map:
  my @M;
  for(my $ch=0; $ch < 256; $ch++) {
  $M[$ch >> 5] |= 1 << ($ch & 0x1f) if chr($ch) =~ /[a-z0-9_-]/i;
  }
  print join(',', map { sprintf "0x%08x",$_ } @M),"\n";
*/
static uint32_t dns_validchar[8] =
  {
   0x00000000,0x03ff2000,0x87fffffe,0x07fffffe,0,0,0,0
  };

/* *********************************************** */

/*
	parse and retrieve a dns name, 
	using the DNS Name Notation and Message Compression Technique
	before exit increment offset of pointer on payload
	
   NB: if return_field pointer points to an area of max_len bytes, and
	retrieved dns name is longer, the returned value is truncated!	
*/
void parseDnsName( u_char *return_field, const int max_len, int *i, const u_int8_t *payload, const u_int payloadLen ) {
	static uint8_t wd=0;	// watchdog 
	u_int j= 0, off, cloff= 0, tmpv;
	int data_len;
	
	DBGTRACER("initial offset: %d, payload (len:%d): %p",*i,payloadLen,payload)
	off=(u_int)*i;
	data_len= getNameLength(off, payload, payloadLen);
	DBGTRACER("name len %d, space: %d",data_len,max_len)

	if ( data_len<0 )	// not valid value, return
		return;
	
	u_char *dnsName= ndpi_calloc(data_len+1,sizeof(u_char));
	DBGPOINTER("allocated %u bytes of memory for pointer(dnsName): %p.", (int)data_len+1, dnsName ) 
	if ( return_field && dnsName) {
		
		while(j < data_len && off < payloadLen && payload[off] != '\0') {
		  uint8_t cl = payload[off++];	//init label counter

		  DBGTRACER("parsing: j/tot: %d/%u, off: %d, value: %02Xh [%c]",j, data_len, off, cl, cl)
		  if( (cl & 0xc0) != 0 ) {
			cloff=(cloff)?cloff:off+1;		// save return offset, first time
			DBGTRACER("new off(HI)=%d",(cl & 0x3f)<<8)
			DBGTRACER("new off(LO)=%d",payload[off])

			tmpv= ( (cl & 0x3f)<<8) + payload[off++];			// change offset
			off = tmpv;
			DBGTRACER("saved offset %d for jump to new off: %d",cloff, off)
			if ((++wd)>=250) {
				// used to exit when the parsing loops!!
				dnsName[j] = '\0';	// terminate dnsName
				printf("ERR(parseDnsName): parsing: %.*s, j/tot: %u/%d, off: %u, value: %02Xh %c\n", data_len, dnsName, j, data_len, off, cl, cl);		  
				wd=0; 
				return;
			}
			continue;
		  } else if (off + cl >= payloadLen) {
			j = 0;	
			break;
		  }

		  if(j && j < data_len) dnsName[j++] = '.';	// replace the label length with dot, except the at first 

		  while(j < data_len && cl != 0) {
			uint8_t c;
			u_int32_t shift;
			
			c = payload[off++];
			shift = ((u_int32_t) 1) << (c & 0x1f);
			dnsName[j++] = tolower((dns_validchar[c >> 5] & shift) ? c : '_');
			cl--;
		  }
		}
		
		dnsName[j] = '\0';	// terminate dnsName
				
		if(j > 0) {
			j = MIN(max_len,j);
			DBGTRACER("initial offset: (%d), len: [%d] ? c0_inc_offset: [%d]", *i, j, cloff)
			*i= (cloff)?cloff:(j+2+*i);
			strncpy((char*)return_field,(char*)dnsName,j);
			DBGTRACER("result: (%d) [%s]; new offset:[%d]", j, dnsName, *i)
		}
	}
	else if (return_field==NULL && max_len==0) {
		// it could be the case of dns name with 0 length, increment pointer
		(*i)++;
	}
	else
		printf("ERR: input pointer [%p] or failed to allocate memory.\n",return_field);
	
	DBGTRACER("final offset: %d",*i)
	
	DBGPOINTER("free memory for pointer(dnsName): %p, %u bytes ",dnsName, (int)data_len+1 )
	ndpi_free(dnsName);	// free memory
	wd=0;
}


/* *********************************************** */

/**
 * this function search for the length of dns name; if finds it and parameters are set, try to allocate memory and return length
 * if there is a packet malformed error, return immediately (-1)
 * if the problem is the memory allocation, set error flag (-3) and continue...checking 
 * if it can return the length of dns name, set it before 
 * return the error condition (0=success)
 * 
 */
int8_t checkDnsNameAndAllocate(u_int off, const u_int8_t *payload, const u_int payloadLen, 
								char **pName, size_t *ret_name_len, uint8_t *packetError, 
								const char* labelDnsName) {

	uint8_t error_flag=0;
	if (packetError!=NULL) *packetError=0;	// reset error flag
	
	if ( payload==NULL ) {
		printf("ERR(checkDnsNameAndAllocate): invalid input parameters %s: off:%u, lenp: %u, p:%p\n", 
			(labelDnsName!=NULL)?labelDnsName:"", off, payloadLen, payload);
		return -1;	// invalid parameters
	}

	int name_len = getNameLength(off, payload, payloadLen);
	if ( name_len<0 ) {
		// error retrieving dns name length
		if (packetError!=NULL) *packetError=1;
		printf("ERR(checkDnsNameAndAllocate): error retrieving dns name %s\n", (labelDnsName!=NULL)?labelDnsName:"");
		return -2;
	}
	
	if( pName!=NULL ) {		
		if ( name_len>0 ) {
			*pName = ndpi_calloc( name_len, sizeof(char) );
			DBGPOINTER("allocated %ubytes memory for pointer(%s): %p",name_len, (labelDnsName!=NULL)?labelDnsName:"", *pName ) 
			if ( *pName==NULL ) {
				// failed to allocate memory
				printf("ERR(checkDnsNameAndAllocate): fail to allocate memory for dns name %s\n", (labelDnsName!=NULL)?labelDnsName:"");
				error_flag=-3;
			}
		}
		else 
			*pName=NULL; // 0 length name is ok		
	}  
		
	if (ret_name_len!=NULL) {
		*ret_name_len= name_len;
	}

	DBGTRACER("OK retrieving dns name %s; err=%d", (labelDnsName!=NULL)?labelDnsName:"", error_flag)
	return error_flag;	// 0: success
}


struct dnsQSList_t *parseDnsQSecs(u_int8_t nitems, int *i, 
		const u_int8_t *payload, const u_int payloadLen, u_int *notfound, struct ndpi_flow_struct *flow ) {
	
	struct dnsQSList_t *retQSList=NULL, *lastQSListItem=NULL;
	u_int k=0, off= (u_int)*i; // init offset 
	u_int8_t no_error;
	no_error= 1;
	DBGTRACER("off initialized = %u", off)
	
	for ( k=0; k<nitems && no_error; k++) {	
		DBGTRACER("next record start at offset=%u", off)		
		struct dnsQuestionSec_t *currQsItem= ndpi_calloc( 1, sizeof(struct dnsQuestionSec_t) ); 
		DBGPOINTER("allocated %lu bytes memory for pointer: %p.",sizeof(struct dnsQuestionSec_t),currQsItem ) 
			
		if ( currQsItem ) {
			size_t data_len;
			uint8_t malformed;	// set to 1, for malformed packet error
			//char *pstr,*tmpstr;				
			DBGTRACER("extracting data of item no. %d/%d",(k+1),nitems)

			/* parse the rrName */
			if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currQsItem->questionName, &data_len, &malformed, "[qsName]") ) {
				parseDnsName( (u_char*)currQsItem->questionName, data_len, (int*)&off, payload, payloadLen );
				DBGTRACER("qsName: [%p] (%u) %.*s",currQsItem->questionName,(u_int)data_len,(u_int)data_len,currQsItem->questionName)
			} else  {
				printf("ERR(parseDnsQSecs): dns name retrieving error: QS NAME \n");
				if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
				ndpi_free(currQsItem);
				no_error=0;
				break;
			}

			if ( off+4 > payloadLen ) {
				printf("ERR(parseDnsQSecs): malformed packet: len (%u) less then need.\n",payloadLen);
				NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
				free_dns_QSec(currQsItem);
				no_error=0;
				break;
			} 
			else if ( no_error ) {
				currQsItem->query_type =  get16((int*)&off, payload); 		// query type
				currQsItem->query_class = get16((int*)&off, payload); 		// class of the query record
			}

			// fill the list
			if ( retQSList ) {
				lastQSListItem= add_QS_elem_to_list(lastQSListItem, currQsItem);
				if (!lastQSListItem) {
					//ERR
					printf("ERR: failed to add a new element [%s], type:%u, class:%u.\n",
							currQsItem->questionName,currQsItem->query_type,currQsItem->query_class);
					
					clear_dns_QS_list(&retQSList,1);
					free_dns_QSec(currQsItem);
					no_error=0;
				}
			} else if (no_error) {
				// list empty: first item
				retQSList= add_QS_elem_to_list(NULL, currQsItem);
				if (!retQSList) {
					//ERR
					printf("ERR: failed to add a new element [%s], type:%u, class:%u.\n",
							currQsItem->questionName,currQsItem->query_type,currQsItem->query_class);
					
					free_dns_QSec(currQsItem);
					no_error=0;
				}
				lastQSListItem= retQSList;
			} else {
				free_dns_QSec(currQsItem);
			}
			currQsItem= NULL;
		}
		else 
			printf("ERR(parseDnsQSecs): fail to allocate memory for a DNS QS.\n");

		DBGTRACER("end of parsing of RR of QS.")
	}
	DBGTRACER("end of parsing of QS.")

	*notfound=nitems-k;	// returns the number of not found
	if (!no_error) {
		clear_dns_QS_list(&retQSList,1);
	}

	// if the numbert of retrieved items, is not equal to those waited: not valid packet!!
	if (*notfound>0) {
		printf("ERR(parseDnsQSecs): missing %u DNS QS parsing the section!\n", *notfound);
		NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
	}

	*i=off;
	DBGINFO("returning result=%u, offset=%u, list=%p", *notfound,*i, retQSList)
	return retQSList;
}

/*
	scan and parse a RR section (Answer,Authority,Additional) of DNS packet
	increment the offset in the payload, after the last rr record successfully parsed

*/
struct dnsRRList_t *parseDnsRRs(uint8_t nitems, int *i, 
		const uint8_t *payload, const u_int payloadLen, u_int *notfound, struct ndpi_flow_struct *flow ) {
	
	struct dnsRRList_t *retRRList=NULL, *lastRRListItem=NULL;
	u_int k=0, off= (u_int)*i; // init offset 
	u_int8_t no_error;
	
	no_error= 1;
	DBGTRACER("offset initialized = %u", off)
	
	for ( k=0; k<nitems && no_error; k++) {	
		DBGTRACER("next record start at offset=%u", off)
		struct dnsRR_t *currItem= ndpi_calloc( 1, sizeof(struct dnsRR_t) ); 
		DBGPOINTER("allocated %lubytes memory for pointer (dnsRR_t): %p.",(unsigned long)sizeof(struct dnsRR_t),currItem )
		if ( currItem ) {
			size_t data_len;
			uint8_t malformed;	// set to 1, for malformed packet error
			char *pstr,*tmpstr;				
			DBGTRACER("extracting data of item no. %d/%d",(k+1),nitems)			

			/* parse the rrName */
			if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->rrName, &data_len, &malformed, "[rrName]") ) {
				parseDnsName( (u_char*)currItem->rrName, data_len, (int*)&off, payload, payloadLen );
				DBGINFO("rrName: [%p] (%u) %s",currItem->rrName,(u_int)data_len,currItem->rrName)
			} else  {
				printf("ERR(parseDnsRRs): dns name retrieving error: RR NAME \n");
				if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
				ndpi_free(currItem->rrName);
				ndpi_free(currItem);
				break;
			}
			if ( off+10 > payloadLen ) {
				printf("ERR(parseDnsRRs): overflow error after retrieving: RR NAME \n");
				if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
				ndpi_free(currItem->rrName);
				ndpi_free(currItem);
				break;
			}
			else {
			currItem->rrType =  get16((int*)&off, payload); 						// resource type
			currItem->rrClass = get16((int*)&off, payload); 						// class of the resource record
			currItem->rrTTL= get32((int*)&off, payload);							// cache time to live			
			currItem->rrRDL= get16((int*)&off, payload);							// resource data length
			
			int offsaved= off;	// used to mark this offset

			DBGINFO("type:%u, class:%u, ttl:%u, RDlen: %u",currItem->rrType,currItem->rrClass,currItem->rrTTL,currItem->rrRDL)

			if ( off+currItem->rrRDL>payloadLen ) {
				ERRLOG("payload length < resource data length!!")
				malformed=1;
				NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
				ndpi_free(currItem->rrName);
				ndpi_free(currItem);
				break;
			}

			switch(currItem->rrType) {
				
				case DNS_TYPE_A:
						if ( off+4>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet A RR \n");	
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					memcpy(&currItem->RData.addressIP, &payload[off], sizeof(uint32_t));
					DBGINFO("A [%p]",&currItem->RData.addressIP)
					off+=4;
					break;
				
				case DNS_TYPE_NS:
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.NSDName, &data_len, &malformed, "[NSDName]") ) {
						parseDnsName( (u_char*)currItem->RData.NSDName, data_len, (int*)&off, payload, payloadLen );
						DBGINFO("NS: (%u) %s",(u_int)data_len,currItem->RData.NSDName)
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: NS DName\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
								no_error=0;
					}
					break;
				
				case DNS_TYPE_CNAME:
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.CName, &data_len, &malformed, "[CName]") ) {
						parseDnsName( (u_char*)currItem->RData.CName, data_len, (int*)&off, payload, payloadLen );
								DBGINFO("CNAME: (%u) %s",(u_int)data_len,currItem->RData.CName)
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: CName\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
								no_error=0;
					}
					break;
				
				case DNS_TYPE_SOA:
					// extract SOA Master name
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.SOA.MName, &data_len, &malformed, "[SOA.MName]") ) {
						parseDnsName( (u_char*)currItem->RData.SOA.MName, data_len, (int*)&off, payload, payloadLen );
								DBGINFO("SOA.MName: (%u) %s",(u_int)data_len, currItem->RData.SOA.MName)
						//TODO: must manage the @ on the first dot.
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: SOA.MName\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
								no_error=0;
					} 
					
					// extract SOA Responsible name
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.SOA.RName, &data_len, &malformed, "[SOA.RName]") ) {
						parseDnsName( (u_char*)currItem->RData.SOA.RName, data_len, (int*)&off, payload, payloadLen );
								DBGINFO("SOA.RName: (%u) %s",(u_int)data_len,currItem->RData.SOA.RName)
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: SOA.RName\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);

						ndpi_free(currItem->RData.SOA.MName);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
								no_error=0;
					} 
						if ( off+20>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet SOA RR \n");	
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->RData.SOA.MName);
							ndpi_free(currItem->RData.SOA.RName);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					currItem->RData.SOA.Serial= get32((int*)&off, payload); 	// serial
					currItem->RData.SOA.Refresh= get32((int*)&off, payload); 	// refresh
					currItem->RData.SOA.Retry= get32((int*)&off, payload); 		// retry
					currItem->RData.SOA.Expire= get32((int*)&off, payload); 	// expire
					currItem->RData.SOA.Minimum= get32((int*)&off, payload); 	// minimum
					break;

				case DNS_TYPE_RP:
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.RP.mailbox, &data_len, &malformed, "[RP mailbox]") ) {
						parseDnsName( (u_char*)currItem->RData.RP.mailbox, data_len, (int*)&off, payload, payloadLen );
								DBGINFO("RP mailbox: (%u) %s",(u_int)data_len,currItem->RData.RP.mailbox)						
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: RP mailbox\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);

						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
								no_error=0; 
					} 					

					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.RP.respPerson, &data_len, &malformed, "[RP respPerson]") ) {
						parseDnsName( (u_char*)currItem->RData.RP.respPerson, data_len, (int*)&off, payload, payloadLen );
								DBGINFO("RP respPerson: (%u) %s",(u_int)data_len,currItem->RData.RP.respPerson)
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: RP respPerson\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);

						ndpi_free(currItem->RData.RP.mailbox);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
								no_error=0;
					} 
					break;

				case DNS_TYPE_PTR:
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.PTRDName, &data_len, &malformed, "[PTRDName]") ) {
						parseDnsName( (u_char*)currItem->RData.PTRDName, data_len, (int*)&off, payload, payloadLen );
								DBGINFO("PTR: (%u) %s",(u_int)data_len,currItem->RData.PTRDName)
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: PTR DName\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);

						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
								no_error=0;
					}
					break;
					
				case DNS_TYPE_HINFO:
					currItem->RData.HINFO.cpu_len= payload[off++];
						if ( off+currItem->RData.HINFO.cpu_len>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet on CPU of HINFO RR \n");	
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
						DBGINFO("DNS_TYPE_HINFO: cpu len: %d",currItem->RData.HINFO.cpu_len)
					currItem->RData.HINFO.cpu= ndpi_calloc(currItem->RData.HINFO.cpu_len+1, sizeof(char));
					if (currItem->RData.HINFO.cpu) {
						memcpy(currItem->RData.HINFO.cpu, &payload[off], currItem->RData.HINFO.cpu_len);
						off+=currItem->RData.HINFO.cpu_len;
							DBGINFO("DNS_TYPE_HINFO: os: (%d) [%s]", currItem->RData.HINFO.cpu_len, currItem->RData.HINFO.cpu)
					} else {
						printf("ERR(parseDnsRRs): fail to allocate memory for HINFO.cpu\n");
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
							no_error=0;
					}

					currItem->RData.HINFO.os_len= payload[off++];
						if ( off+currItem->RData.HINFO.os_len>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet on OS of HINFO RR \n");	
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->RData.HINFO.cpu);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					DBGINFO("DNS_TYPE_HINFO os len: %d",currItem->RData.HINFO.os_len)
					currItem->RData.HINFO.os= ndpi_calloc(currItem->RData.HINFO.os_len+1, sizeof(char));
					if (currItem->RData.HINFO.os) {
						memcpy(currItem->RData.HINFO.os, &payload[off],currItem->RData.HINFO.os_len);
						off+=currItem->RData.HINFO.os_len;
							DBGINFO("DNS_TYPE_HINFO: os: (%d) [%s]", currItem->RData.HINFO.os_len, currItem->RData.HINFO.os)
					} else {
						printf("ERR(parseDnsRRs): fail to allocate memory for HINFO.os\n");
						ndpi_free(currItem->RData.HINFO.cpu);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
							no_error=0;
					}
					break;
					
				case DNS_TYPE_MX:
					currItem->RData.MX.preference= get16((int*)&off, payload); 
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.MX.exchange, &data_len, &malformed, "[MX]") ) {
						parseDnsName( (u_char*)currItem->RData.MX.exchange, data_len, (int*)&off, payload, payloadLen );
								DBGINFO("MX: (%u) %s - Pref: %d",(u_int)data_len,currItem->RData.MX.exchange,currItem->RData.MX.preference)
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: MX\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
								no_error=0;
					}
					break;
				
				case DNS_TYPE_TXT:
					currItem->RData.TXT.txt_len=payload[off++];
						if ( off+currItem->RData.TXT.txt_len>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet on TXT RR \n");							
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					if( currItem->RData.TXT.txt_len>0) {
						currItem->RData.TXT.txtData= ndpi_calloc((1+currItem->RData.TXT.txt_len), sizeof(char));
						if (currItem->RData.TXT.txtData) {
							strncpy(currItem->RData.TXT.txtData, (char*)&payload[off], currItem->RData.TXT.txt_len);
							currItem->RData.TXT.txtData[currItem->RData.TXT.txt_len]='\0';
								DBGINFO("TXT %p ->[(%u) %.*s]",currItem->RData.TXT.txtData,currItem->RData.TXT.txt_len,currItem->RData.TXT.txt_len,currItem->RData.TXT.txtData)
							off+= currItem->RData.TXT.txt_len;
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for TXT [ ]\n");
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
								no_error=0;
						}
					} 
					else currItem->RData.TXT.txtData= NULL; 
					break;
				
				case DNS_TYPE_AFSDB:
						if ( off+3>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet on AFSDB RR \n");
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					DBGTRACER("DNS_TYPE_AFSDB: len: %d",currItem->rrRDL)
					currItem->RData.AFSDB.subtype= get16((int*)&off, payload); 
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.AFSDB.hostname, &data_len, &malformed, "[AFSDBHOST]") ) {
						parseDnsName( (u_char*)currItem->RData.AFSDB.hostname, data_len, (int*)&off, payload, payloadLen );
						DBGINFO("MX: (%u) %s - Pref: %d",(u_int)data_len,currItem->RData.MX.exchange,currItem->RData.MX.preference)
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: AFSDB HOST\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						no_error=0;
					}
					break;
					
				case DNS_TYPE_AAAA:
					if ( currItem->rrRDL <= sizeof(struct ndpi_ip6_addrBIS) ) {
						memcpy(&currItem->RData.addressIPv6, &payload[off], currItem->rrRDL);
						DBGINFO("AAAA [%p]",&currItem->RData.addressIPv6)
						off+=16;
					}
					else {
						malformed=1;
						printf("ERR(parseDnsRRs): dns retrieving error: AAAA\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						no_error=0;
					}
					break;

				case DNS_TYPE_LOC:
						if ( off+currItem->rrRDL>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet on LOC RR \n");
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					DBGTRACER("DNS_TYPE_LOC len: %d",currItem->rrRDL)
					currItem->RData.LOC.version= payload[off++];					
					currItem->RData.LOC.size= payload[off++];
					currItem->RData.LOC.hprecs= payload[off++];
					currItem->RData.LOC.vprecs= payload[off++];
					currItem->RData.LOC.latit= get32((int*)&off, payload);
					currItem->RData.LOC.longit= get32((int*)&off, payload);
					currItem->RData.LOC.alt= get32((int*)&off, payload);
					DBGINFO("DNS_TYPE_LOC: vers:%d, size:%d, H-prex:%d, V-prex:%d, LAT:%u, LONG:%u, ALT:%u", \
									currItem->RData.LOC.version, currItem->RData.LOC.size, \
									currItem->RData.LOC.hprecs,	currItem->RData.LOC.vprecs, \
									currItem->RData.LOC.latit, currItem->RData.LOC.longit, currItem->RData.LOC.alt)
					if (currItem->RData.LOC.version) {
						// if version 0 ok, otherwise the dissector can fail...
						// so restore the offset for error
						off = offsaved+ currItem->rrRDL;	
					}
					break;
					
				case DNS_TYPE_SRVS:
						if ( off+7>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet on SRVS RR \n");
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
						DBGINFO("DNS_TYPE_SRVS len: %d",currItem->rrRDL)
					data_len= strlen(currItem->rrName);
					tmpstr= ndpi_calloc(data_len+1,sizeof(char));
					if (tmpstr!=NULL) {
						strncpy(tmpstr,currItem->rrName,data_len);
						pstr= strtok(tmpstr,".");
						if ( pstr!=NULL) {
							data_len= strlen(pstr);
							if ( data_len>0 ) {
								currItem->RData.SRVS.service= ndpi_calloc(data_len+1, sizeof(char));
								if ( currItem->RData.SRVS.service ) {
									strncpy(currItem->RData.SRVS.service,pstr,data_len);
									DBGINFO("SRVS service: (%u) %s",(u_int)data_len,currItem->RData.SRVS.service)
								} else {
									printf("ERR(parseDnsRRs): fail to allocate memory for SRVS:service \n");
									ndpi_free(tmpstr);
									ndpi_free(currItem->rrName);
									ndpi_free(currItem);
									no_error=0;
									break;
								}
							}
							else currItem->RData.SRVS.service= NULL;
						}
						pstr= strtok(NULL,".");
						if ( pstr!=NULL) {
							data_len= strlen(pstr);
							if ( data_len>0 ) {
								currItem->RData.SRVS.protocol= ndpi_calloc(data_len+1, sizeof(char));
								if ( currItem->RData.SRVS.protocol ) {
									strncpy(currItem->RData.SRVS.protocol,pstr,data_len);
									DBGINFO("SRVS protocol: (%u) %s",(u_int)data_len,currItem->RData.SRVS.protocol)
								} else {
									printf("ERR(parseDnsRRs): fail to allocate memory for SRVS:protocol \n");
									ndpi_free(currItem->RData.SRVS.service);
									ndpi_free(tmpstr);
									ndpi_free(currItem->rrName);
									ndpi_free(currItem);
									no_error=0;
									break;
								}
							} 
							else currItem->RData.SRVS.protocol= NULL;
						}
						ndpi_free(tmpstr);
					} else {
						printf("ERR(parseDnsRRs): fail to allocate memory for parsing rrName (service,protocol) \n");
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						no_error=0;
						break; 
					}
					currItem->RData.SRVS.priority= get16((int*)&off, payload);
					currItem->RData.SRVS.weight= get16((int*)&off, payload);
					currItem->RData.SRVS.port= get16((int*)&off, payload);
					DBGINFO("SRVS: priority: %u, weight: %u, port: %u",(u_int)currItem->RData.SRVS.priority,currItem->RData.SRVS.weight,currItem->RData.SRVS.port)

					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.SRVS.target, &data_len, &malformed, "[SRVSTARGET]") ) {
						parseDnsName( (u_char*)currItem->RData.SRVS.target, data_len, (int*)&off, payload, payloadLen );
						DBGINFO("SRVS target: (%u) %s",(u_int)data_len,currItem->RData.SRVS.target)
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: SRVS TARGET\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->RData.SRVS.protocol);
						ndpi_free(currItem->RData.SRVS.service);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						no_error=0;
						break; 
					} 
					break;

				case DNS_TYPE_NAPTR:
						if ( off+5>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet on NAPTR RR \n");
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					DBGINFO("DNS_TYPE_NAPTR:\n")	
					currItem->RData.NAPTR.order= get16((int*)&off, payload);
					currItem->RData.NAPTR.preference= get16((int*)&off, payload);
					DBGINFO("NAPTR order: %u, preference: %u",currItem->RData.NAPTR.order,currItem->RData.NAPTR.preference)

					currItem->RData.NAPTR.flags_len= payload[off++];
					if (currItem->RData.NAPTR.flags_len>0 && 
						((currItem->RData.NAPTR.flags_len+off)<payloadLen)) {
						currItem->RData.NAPTR.flags= ndpi_calloc(currItem->RData.NAPTR.flags_len+1, sizeof(char));
						if ( currItem->RData.NAPTR.flags ) {
							memcpy(currItem->RData.NAPTR.flags,&payload[off],currItem->RData.NAPTR.flags_len);
							off+=currItem->RData.NAPTR.flags_len;
							DBGINFO("NAPTR flags: (%u) %p ->[%02X]",(u_int)currItem->RData.NAPTR.flags_len,currItem->RData.NAPTR.flags,*currItem->RData.NAPTR.flags)
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for NAPTR:flags \n");
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break; 
						}
					} else if ( (currItem->RData.NAPTR.flags_len + off) >= payloadLen ) {
						malformed=1;
						printf("ERR(parseDnsRRs): malformed packet on NAPTR RR \n");
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						no_error=0;
						break;
					}
					else currItem->RData.NAPTR.flags=NULL;

					currItem->RData.NAPTR.service_len= payload[off++];
						if ( off+currItem->RData.NAPTR.service_len>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet on NAPTR RR(service) \n");
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->RData.NAPTR.flags);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					if (currItem->RData.NAPTR.service_len>0) {
						currItem->RData.NAPTR.service= ndpi_calloc(1+currItem->RData.NAPTR.service_len, sizeof(char));
						if ( currItem->RData.NAPTR.service ) {
							memcpy(currItem->RData.NAPTR.service,&payload[off],currItem->RData.NAPTR.service_len);
							off+=currItem->RData.NAPTR.service_len;
							DBGINFO("NAPTR service: (%u) %p ->[%02X]",(u_int)currItem->RData.NAPTR.service_len,currItem->RData.NAPTR.service,*currItem->RData.NAPTR.service)
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for NAPTR:service \n");
							ndpi_free(currItem->RData.NAPTR.flags);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					}
					else currItem->RData.NAPTR.service=NULL;

					currItem->RData.NAPTR.re_len= payload[off++];
						if ( off+currItem->RData.NAPTR.re_len>payloadLen ) {
							printf("ERR(parseDnsRRs): malformed packet on NAPTR RR(re) \n");
							malformed=1;
							NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
							ndpi_free(currItem->RData.NAPTR.flags);
							ndpi_free(currItem->RData.NAPTR.service);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					if (currItem->RData.NAPTR.re_len>0) {
						currItem->RData.NAPTR.regex= ndpi_calloc(currItem->RData.NAPTR.re_len+1, sizeof(char));
						if ( currItem->RData.NAPTR.regex ) {
							memcpy(currItem->RData.NAPTR.regex,&payload[off],currItem->RData.NAPTR.re_len);
							off+=currItem->RData.NAPTR.re_len;
							DBGINFO("NAPTR regex: (%u) %p ->[%02X]",(u_int)currItem->RData.NAPTR.re_len,currItem->RData.NAPTR.regex,*currItem->RData.NAPTR.regex)
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for NAPTR:regex \n");
							ndpi_free(currItem->RData.NAPTR.flags);
							ndpi_free(currItem->RData.NAPTR.service);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							no_error=0;
							break;
						}
					}
					else currItem->RData.NAPTR.regex= NULL;

					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.NAPTR.replacement, &data_len, &malformed, "[NAPTRreplacement]") ) {
						parseDnsName( (u_char*)currItem->RData.NAPTR.replacement, data_len, (int*)&off, payload, payloadLen );
						currItem->RData.NAPTR.re_replace_len=data_len-1;
						DBGINFO("NAPTR replacement: (%u) %s",(u_int)data_len,currItem->RData.NAPTR.replacement)
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: NAPTR:replacement\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->RData.NAPTR.flags);
						ndpi_free(currItem->RData.NAPTR.service);
						ndpi_free(currItem->RData.NAPTR.regex);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						no_error=0;
						break;
					}

					off = offsaved+ currItem->rrRDL;	// restore the offset for error
					break;
					
				case DNS_TYPE_AXFR:
					//memcpy(&currItem->RData.addressIPv6, &payload[off], currItem->rrRDL);
						DBGINFO("AFXR ");
					off+=16;
					break;
								
				default:
						printf("DNS RR type: [%02Xh] not managed (ID:%u]).\n",currItem->rrType, flow->protos.dns.tr_id);
						currItem->RData.unKnownTypeData= (uint8_t*) &payload[off];
#ifdef DEBUG_DNS_INFO						
						printRawData(currItem->RData.unKnownTypeData,currItem->rrRDL);
#endif
						off = offsaved+ currItem->rrRDL;
				}
			}
			
			DBGINFO("RR item (%p): [%s] ready to add to dnsRR list: (%p)",currItem, currItem->rrName, lastRRListItem)

			// fill the list
			if ( retRRList && no_error ) {
				lastRRListItem= add_RR_elem_to_list(lastRRListItem, currItem);
				if (!lastRRListItem) {
					//ERR
					printf("ERR: failed to add a new element [%s] to list, type:%u, class:%u, ttl:%u, RDlen: %u.\n",
							currItem->rrName,currItem->rrType,currItem->rrClass,currItem->rrTTL,currItem->rrRDL);
					
					clear_dns_RR_list(&retRRList,1);
					free_dns_RR(currItem);
					retRRList= NULL;
					break;	// exit from loop
				}
			} else if (no_error) {
				// list empty: first item
				retRRList= add_RR_elem_to_list(NULL, currItem);
				if (!retRRList) {
					//ERR
					printf("ERR: failed to add a new element [%s], creating a new list, type:%u, class:%u, ttl:%u, RDlen: %u.\n",
							currItem->rrName,currItem->rrType,currItem->rrClass,currItem->rrTTL,currItem->rrRDL);
					
					clear_dns_RR_list(&retRRList,1);
					free_dns_RR(currItem);
					retRRList= NULL;
					no_error=0;
					break;	// exit from loop
				}
				lastRRListItem= retRRList;
			}
		}
		else 
			printf("ERR(parseDnsRRs): fail to allocate memory for a DNS RR.\n");
		
		DBGTRACER("end of parsing of RR.")
	}
	DBGTRACER("end of parsing of section of RR.")

	*notfound=nitems-k;	// returns the number of not found

	// if the numbert of retrieved items, is not equal to those waited: not valid packet!!
	if (*notfound>0) {
		printf("ERR(parseDnsRRs): missing %u DNS RR parsing the section!\n", *notfound);
		NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
	}

	*i=off;
	DBGINFO("returning result=%u, offset=%u, dnsRR list=%p", *notfound,*i, retRRList)
	return retRRList;
}

/* *********************************************** */

static int search_valid_dns(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow,
			    struct ndpi_dns_packet_header *dns_header,
			    int payload_offset, u_int8_t *is_query) {
  int x = payload_offset;
  
  memcpy(dns_header, (struct ndpi_dns_packet_header*)&flow->packet.payload[x],
	 sizeof(struct ndpi_dns_packet_header));

  dns_header->tr_id = ntohs(dns_header->tr_id);
  dns_header->flags = ntohs(dns_header->flags);
  dns_header->num_queries = ntohs(dns_header->num_queries);
  dns_header->num_answers = ntohs(dns_header->num_answers);
  dns_header->authority_rrs = ntohs(dns_header->authority_rrs);
  dns_header->additional_rrs = ntohs(dns_header->additional_rrs);

  x += sizeof(struct ndpi_dns_packet_header);
 
  DBGINFO("ID=#%02Xh, counters: [%d,%d,%d,%d], flags: %04Xh",dns_header->tr_id, dns_header->num_queries, dns_header->num_answers, dns_header->authority_rrs, dns_header->additional_rrs,dns_header->flags)
  
  /* 0x0000 QUERY */
  if((dns_header->flags & FLAGS_MASK) == 0x0000)
    *is_query = 1;
  /* 0x8000 RESPONSE */
  else if((dns_header->flags & FLAGS_MASK) == 0x8000)
    *is_query = 0;
  else {
    NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
    return(1 /* invalid */);
  }

#ifdef __DNS_H__  
  /* setting ID and flag to flow struct */
  flow->protos.dns.tr_id= dns_header->tr_id;
  flow->protos.dns.flags= dns_header->flags;
#endif
  
  if(*is_query) {
	flow->protos.dns.dns_request_complete=0;
	flow->protos.dns.dns_response_complete=0;
	DBGTRACER("query processing. ")
    /* DNS Request */
    if((dns_header->num_queries > 0) && (dns_header->num_queries <= NDPI_MAX_DNS_REQUESTS)
       && (((dns_header->flags & 0x2800) == 0x2800 /* Dynamic DNS Update */)
	   || ((dns_header->num_answers == 0) && (dns_header->authority_rrs == 0)))) {

#if 0
 	  u_int16_t dns_class;

      /* This is a good query */
      while(x+4 < flow->packet.payload_packet_len) {
        if(flow->packet.payload[x] == '\0') {
			x++;
			flow->protos.dns.query_type = get16((int*)&x, flow->packet.payload);
			
			//if (x+2 < flow->packet.payload_packet_len) {
				dns_class =  get16((int*)&x, flow->packet.payload); // x -=2;
			flow->protos.dns.query_class = dns_class;
			//}
		  
#ifdef DNS_DEBUG
          NDPI_LOG_DBG2(ndpi_struct, "query_type=%2d\n", flow->protos.dns.query_type);
#endif		
			flow->protos.dns.dns_request_complete=1;
			flow->protos.dns.dns_request_seen=flow->protos.dns.dns_request_print=0;
			
			DBGTRACER("query processed and complete.");
			break;
		} else
	  		x++;
      }
#else
	  u_int notfound = 1;

	  //if(dns_header->num_queries > 0) {
		if ( flow->protos.dns.dnsQueriesList!=NULL ) clear_dns_QS_list(&flow->protos.dns.dnsQueriesList,1);
		flow->protos.dns.dnsQueriesList= parseDnsQSecs(dns_header->num_queries,&x, flow->packet.payload, flow->packet.payload_packet_len, &notfound, flow);
		DBGINFO("parsing dnsQS-R (%p) done... ", flow->protos.dns.dnsQueriesList)
		
		if ( notfound>0 || !flow->protos.dns.dnsQueriesList) {
			ERRLOG("ID=#%02Xh, malformed/risky? queries expected:%u, current offset:%u vs packet len:%u", dns_header->tr_id, dns_header->num_queries, x, flow->packet.payload_packet_len )
			NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
			clear_all_dns_list(flow);
			return(1 /* invalid */);			
		} 
		// for compatibility with previous code, set the following variables with the first QR, from Query Section
		struct dnsQSList_t* currQsList = flow->protos.dns.dnsQueriesList;
		if ( currQsList!=NULL ) {
			struct dnsQuestionSec_t* firstQSItem = currQsList->qsItem;
			if (firstQSItem) {
				flow->protos.dns.query_type= firstQSItem->query_type;
				flow->protos.dns.query_class= firstQSItem->query_class;			
			}
		}
		flow->protos.dns.dns_request_complete= 1;
		flow->protos.dns.dns_request_seen=flow->protos.dns.dns_request_print=0;
		DBGTRACER("query processed and complete.");
	  //} else
	  //  flow->protos.dns.dnsQueriesList= NULL;
#endif 

	  if(dns_header->additional_rrs > 0) {

		if ( flow->protos.dns.dnsAdditionalRRList!=NULL ) clear_dns_RR_list(&flow->protos.dns.dnsAdditionalRRList,1);
		flow->protos.dns.dnsAdditionalRRList= parseDnsRRs(dns_header->additional_rrs,&x, flow->packet.payload, flow->packet.payload_packet_len, &notfound,flow);
		DBGINFO("parsing additional dnsRR-R (%p) done... ", flow->protos.dns.dnsAdditionalRRList)

		if (notfound>0 || !flow->protos.dns.dnsAdditionalRRList) {
			ERRLOG("ID=#%02Xh, malformed/risky? additional RR expected:%u, current offset:%u vs packet len:%u", dns_header->tr_id, dns_header->additional_rrs, x, flow->packet.payload_packet_len )			
			NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
			clear_all_dns_list(flow);
			return(1 /* invalid */);			
		}		
	  } else
		  flow->protos.dns.dnsAdditionalRRList= NULL;  

    } else {

	  ERRLOG("ID=#%02Xh, %s malformed/risky? queries_num:%u, hflag:%02xh, answer_num:%u, auth_num:%u, add_num:%u; current offset:%u vs packet len:%u ", dns_header->tr_id, (*is_query?"R":"A"), dns_header->num_queries, dns_header->flags, dns_header->num_answers, dns_header->authority_rrs, dns_header->additional_rrs, x, flow->packet.payload_packet_len)
      NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
	  clear_all_dns_list(flow);
      return(1 /* invalid */);
    }
	
	DBGINFO("dns request parsed...offset=%u/%u ", x,flow->packet.payload_packet_len)

  } else {
	u_int notfound = 1;

	DBGTRACER("response processing. ")
    /* DNS Reply */
    flow->protos.dns.reply_code = dns_header->flags & 0x0F; // 0= no error

    if((dns_header->num_queries > 0) && (dns_header->num_queries <= NDPI_MAX_DNS_REQUESTS) /* Don't assume that num_queries must be zero */
       && ((((dns_header->num_answers > 0) && (dns_header->num_answers <= NDPI_MAX_DNS_REQUESTS))
	    || ((dns_header->authority_rrs > 0) && (dns_header->authority_rrs <= NDPI_MAX_DNS_REQUESTS))
	    || ((dns_header->additional_rrs > 0) && (dns_header->additional_rrs <= NDPI_MAX_DNS_REQUESTS))))
       ) {
      /* This is a good reply: we dissect it both for request and response */

      /* Leave the statement below commented necessary in case of call to ndpi_get_partial_detection() */
      //x++;
#if 1

 	//if(dns_header->num_queries > 0) {
		if ( flow->protos.dns.dnsQueriesList!=NULL ) clear_dns_QS_list(&flow->protos.dns.dnsQueriesList,1);
		DBGTRACER("parsing QS records... ")
		flow->protos.dns.dnsQueriesList= parseDnsQSecs(dns_header->num_queries ,&x,flow->packet.payload,flow->packet.payload_packet_len, &notfound, flow);
		DBGINFO("parsing dnsQS-A (%p) done... ", flow->protos.dns.dnsQueriesList)

		flow->protos.dns.dns_response_complete &= !(notfound>0);
		if (notfound>0 || !flow->protos.dns.dnsQueriesList) {
			ERRLOG("ID=#%02Xh, malformed/risky? queries expected:%u, current offset:%u vs packet len:%u", dns_header->tr_id, dns_header->num_queries, x, flow->packet.payload_packet_len )
			NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
			clear_all_dns_list(flow);
			return(1 /* invalid */);			
		}
		
	/*} else {
		  flow->protos.dns.dnsQueriesList= NULL;
		  x += 4;
	}*/

#else
	  // skip 'Question Name' section, because do its extraction after
	  if(x < flow->packet.payload_packet_len && flow->packet.payload[x] != '\0') {
		while((x < flow->packet.payload_packet_len)
			  && (flow->packet.payload[x] != '\0')) {
		  x++;
		}
		x++;
      }
      x += 4;
	  // end skip 'Question Name' section
#endif

	  flow->protos.dns.dns_response_complete=1;	// response headers complete initialization
      if(dns_header->num_answers > 0) {

#ifdef __DNS_H__
		
		if ( flow->protos.dns.dnsAnswerRRList!=NULL ) clear_dns_RR_list(&flow->protos.dns.dnsAnswerRRList,1);
	  	/* WARNING: if there is a flow active it need to free allocated memory! */
		DBGTRACER("parsing ANSWER RR records... ")
		flow->protos.dns.dnsAnswerRRList= parseDnsRRs(dns_header->num_answers,&x,flow->packet.payload,flow->packet.payload_packet_len, &notfound, flow);
		DBGINFO("parsing answer dnsRR-A (%p) done... ", flow->protos.dns.dnsAnswerRRList)

		flow->protos.dns.dns_response_complete &= !(notfound>0);
		if (notfound>0 || !flow->protos.dns.dnsAnswerRRList) {
			ERRLOG("ID=#%02Xh, malformed/risky? queries expected:%u, current offset:%u vs packet len:%u", dns_header->tr_id, dns_header->num_answers, x, flow->packet.payload_packet_len )
			NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
			clear_all_dns_list(flow);
			return(1 /* invalid */);			
		}

		// for compatibility with previous code, set the following variables with the first answer
		struct dnsRRList_t* currList = flow->protos.dns.dnsAnswerRRList;
		while ( currList!=NULL ) {
			struct dnsRR_t* firstRR = currList->rrItem;
			if (firstRR) {
				flow->protos.dns.rsp_type= firstRR->rrType;
				flow->protos.dns.query_class= firstRR->rrClass;

				 ndpi_check_dns_type(ndpi_struct, flow, firstRR->rrType);
				
				if ( (((firstRR->rrType == 0x1) && (firstRR->rrRDL == 4)) /* A */
#ifdef NDPI_DETECTION_SUPPORT_IPV6
					|| ((firstRR->rrType == 0x1c) && (firstRR->rrRDL == 16)) /* AAAA */
#endif
				)) {
					memcpy(&flow->protos.dns.rsp_addr, &firstRR->RData, firstRR->rrRDL);
					break;
				}				
			}
			currList = currList->nextItem;
		}		
#else		  
		u_int16_t rsp_type;
		u_int16_t num;

		for(num = 0; num < dns_header->num_answers; num++) {
		  u_int16_t data_len;

		  if((x+6) >= flow->packet.payload_packet_len) {
			break;
		  }

		  if((data_len = getNameLength(x, flow->packet.payload, flow->packet.payload_packet_len)) == 0) {
			break;
		  } else
			x += data_len;

		  if((x+2) >= flow->packet.payload_packet_len) {
			break;
		  }

	  rsp_type = get16(&x, flow->packet.payload);

#ifdef DNS_DEBUG
	  NDPI_LOG_INFO(ndpi_struct, "[DNS] [response] response_type=%d\n", rsp_type);
#endif

	  ndpi_check_dns_type(ndpi_struct, flow, rsp_type);
	  
		  flow->protos.dns.rsp_type = rsp_type;
		  
		  //dns_class =  get16((int*)&x, flow->packet.payload); x -=2;
		  //flow->protos.dns.query_class = dns_class;

		  /* here x points to the response "class" field */
		  if((x+12) <= flow->packet.payload_packet_len) {
			x += 6;
			data_len = get16((int*)&x, flow->packet.payload);
			
			if((x + data_len) <= flow->packet.payload_packet_len) {
			  // printf("[rsp_type: %u][data_len: %u]\n", rsp_type, data_len);

			  if(rsp_type == 0x05 /* CNAME */) {
				x += data_len;
				continue; /* Skip CNAME */
			  }
			  
			  if((((rsp_type == 0x1) && (data_len == 4)) /* A */
#ifdef NDPI_DETECTION_SUPPORT_IPV6
			  || ((rsp_type == 0x1c) && (data_len == 16)) /* AAAA */
#endif
			  )) {
			memcpy(&flow->protos.dns.rsp_addr, flow->packet.payload + x, data_len);
			  }
			}
		  }
		  
		  break;
		}
#endif		
      }
#ifdef __DNS_H__
	  else
		  flow->protos.dns.dnsAnswerRRList= NULL;	

	  if(dns_header->authority_rrs > 0) {
		if ( flow->protos.dns.dnsAuthorityRRList!=NULL ) clear_dns_RR_list(&flow->protos.dns.dnsAuthorityRRList,1);    
		DBGTRACER("parsing AUTHORITY RR records... ")   
		flow->protos.dns.dnsAuthorityRRList= parseDnsRRs(dns_header->authority_rrs,&x, flow->packet.payload, flow->packet.payload_packet_len, &notfound,flow);
		DBGINFO("parsing authority dnsRR-A (%p) done... ", flow->protos.dns.dnsAuthorityRRList)

		flow->protos.dns.dns_response_complete &= !(notfound>0);
		if (notfound>0 || !flow->protos.dns.dnsAuthorityRRList) {
			ERRLOG("ID=#%02Xh, malformed/risky? auth RR expected:%u, current offset:%u vs packet len:%u", dns_header->tr_id, dns_header->authority_rrs, x, flow->packet.payload_packet_len )
			NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
			clear_all_dns_list(flow);
			return(1 /* invalid */);			
		}
	  } else
		  flow->protos.dns.dnsAuthorityRRList= NULL;
		
	  if(dns_header->additional_rrs > 0) {
		if ( flow->protos.dns.dnsAdditionalRRList!=NULL ) clear_dns_RR_list(&flow->protos.dns.dnsAdditionalRRList,1);
		DBGTRACER("parsing ADDITIONAL RR records... ") 
		flow->protos.dns.dnsAdditionalRRList= parseDnsRRs(dns_header->additional_rrs,&x, flow->packet.payload, flow->packet.payload_packet_len, &notfound,flow);
		DBGINFO("parsing additional dnsRR-A (%p) done... ", flow->protos.dns.dnsAdditionalRRList)
		
		flow->protos.dns.dns_response_complete &= !(notfound>0);
		if (notfound>0 || !flow->protos.dns.dnsAdditionalRRList) {
			ERRLOG("ID=#%02Xh, malformed/risky? additional RR expected:%u, current offset:%u vs packet len:%u", dns_header->tr_id, dns_header->additional_rrs, x, flow->packet.payload_packet_len )
			NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
			clear_all_dns_list(flow);
			return(1 /* invalid */);			
		}
		
	  } else
		  flow->protos.dns.dnsAdditionalRRList= NULL;	
		  
#endif
     DBGTRACER("packet processed. ")
	 flow->protos.dns.dns_response_seen=flow->protos.dns.dns_response_print=0;

      if((flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_DNS)
	 || (flow->packet.detected_protocol_stack[1] == NDPI_PROTOCOL_DNS)) {
	/* Request already set the protocol */
	// flow->extra_packets_func = NULL; /* Removed so the caller can keep dissecting DNS flows */
      } else {
	/* We missed the request */
	u_int16_t s_port = flow->packet.udp ? ntohs(flow->packet.udp->source) : ntohs(flow->packet.tcp->source);

	ndpi_set_detected_protocol(ndpi_struct, flow, checkPort(s_port), NDPI_PROTOCOL_UNKNOWN);
      }
    }
	DBGINFO("dns response parsed...offset=%u/%u ", x,flow->packet.payload_packet_len)
  }

  if ( flow->packet.payload_packet_len-x > 2 ) {
	DBGINFO("ID=#%02Xh, malformed/risky? current offset:%u vs packet len:%u ", dns_header->tr_id, x, flow->packet.payload_packet_len)
	// NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
	// return(1 /* invalid */);
  }
  DBGTRACER("exiting complete flags -> req:%d, resp:%d.",flow->protos.dns.dns_request_complete,flow->protos.dns.dns_response_complete)

  /* Valid */
  return(0);
}

/* *********************************************** */

static int search_dns_again(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  /* possibly dissect the DNS reply */
  ndpi_search_dns(ndpi_struct, flow);

  /* Possibly more processing */
  return(1);
}

/* *********************************************** */

void init_dns_tcp_memory(struct ndpi_flow_struct *flow) {
	message_t *dns_segments_buf = &(flow->l4.tcp.dns_segments_buf[flow->packet.packet_direction]);	
	if (dns_segments_buf->buffer) free(dns_segments_buf->buffer);
	dns_segments_buf->buffer=NULL;
	dns_segments_buf->buffer_used=dns_segments_buf->buffer_len=dns_segments_buf->max_expected=0;
	DBGTRACER("dns buffer (%d) initialized",flow->packet.packet_direction)
}

void ndpi_search_dns_tcp_memory(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  message_t *dns_segments_buf = &(flow->l4.tcp.dns_segments_buf[packet->packet_direction]);

  /* TCP */
#ifdef DEBUG_DNS_MEMORY
  printf("[DNS Mem] Handling TCP/DNS flow [payload_len: %u][buffer_len: %u][direction: %u]\n",
	 packet->payload_packet_len,
	 dns_segments_buf->buffer_len,
	 packet->packet_direction);
#endif
  
  DBGTRACER("buffer[dir:%d]: %p", packet->packet_direction,dns_segments_buf->buffer)

  if(dns_segments_buf->buffer == NULL) {
    /* Allocate buffer */
    dns_segments_buf->buffer_len = 2048, dns_segments_buf->buffer_used = 0;
    dns_segments_buf->buffer = (u_int8_t*)ndpi_calloc(dns_segments_buf->buffer_len, sizeof(u_int8_t));
	DBGPOINTER("allocated %d bytes ->(%d) %p\n", dns_segments_buf->buffer_len, packet->packet_direction, dns_segments_buf->buffer)
 
    if(dns_segments_buf->buffer == NULL) {
      dns_segments_buf->buffer_len = 0;
      return;
    }
	
#ifdef DEBUG_DNS_MEMORY
    printf("[DNS Mem] Allocating %u buffer\n", dns_segments_buf->buffer_len);
#endif
  }

  if(flow->packet.tcp != NULL 
	&& packet->payload_packet_len>2 
	&& dns_segments_buf->buffer_used==0 ) {
		int off=0;
		// only tcp and the first time!!
		dns_segments_buf->max_expected = get16(&off, packet->payload);
  }

  u_int avail_bytes = dns_segments_buf->buffer_len - dns_segments_buf->buffer_used;
  if(avail_bytes < packet->payload_packet_len) {
    u_int new_len = dns_segments_buf->buffer_len + packet->payload_packet_len+1;
	DBGPOINTER("old memory pointer for dir: %d -> %p, len: %u\n", packet->packet_direction, dns_segments_buf->buffer,dns_segments_buf->buffer_len)
    void *newbuf  = ndpi_realloc(dns_segments_buf->buffer, dns_segments_buf->buffer_len, new_len);
	DBGPOINTER("allocated %d bytes for dir: %d -> %p\n", new_len, packet->packet_direction, dns_segments_buf->buffer)

    if(!newbuf) return;

#ifdef DEBUG_DNS_MEMORY
    printf("[DNS Mem] Enlarging %u -> %u buffer\n", dns_segments_buf->buffer_len, new_len);
#endif

    dns_segments_buf->buffer = (u_int8_t*)newbuf, 
	dns_segments_buf->buffer_len = new_len;
    avail_bytes = dns_segments_buf->buffer_len - dns_segments_buf->buffer_used;
  }

  if(avail_bytes >= packet->payload_packet_len) {
    memcpy(&dns_segments_buf->buffer[dns_segments_buf->buffer_used],
	    packet->payload, packet->payload_packet_len);

    dns_segments_buf->buffer_used += packet->payload_packet_len;
    DBGINFO("DNS payload added: %d bytes to buffer[%d]: %u/%u; limit:%u", packet->payload_packet_len,packet->packet_direction,dns_segments_buf->buffer_used,dns_segments_buf->buffer_len, dns_segments_buf->max_expected)
    
#ifdef DEBUG_DNS_MEMORY
    printf("[DNS Mem] Copied data to buffer [%u/%u bytes]\n",
	   dns_segments_buf->buffer_used, dns_segments_buf->buffer_len);
#endif     
  }
}

static u_int8_t *oldPayload= NULL;
static u_int16_t oldPayloadLen= 0;
static int oldPayloadOffset=0;

static void savePacketPayload(struct ndpi_flow_struct *flow, const int off) {
	oldPayload= (u_int8_t *) flow->packet.payload;
	oldPayloadLen= flow->packet.payload_packet_len;
	oldPayloadOffset= off;
	DBGINFO("saved: p:%p len:%u", oldPayload, oldPayloadLen)
}
static void restorePacketPayload(struct ndpi_flow_struct *flow, int *ploff, u_int8_t fInitBuffer) {
	flow->packet.payload= oldPayload;
	flow->packet.payload_packet_len= oldPayloadLen;
	*ploff = oldPayloadOffset;
	DBGINFO("restored: p:%p len:%u", oldPayload, oldPayloadLen)
	if ( fInitBuffer ) init_dns_tcp_memory(flow);
}
static u_int8_t swap_packet_ref(struct ndpi_flow_struct *flow, int *ploff) {
	DBGINFO("off:%d", *ploff);
	message_t *dns_segments_buf = &(flow->l4.tcp.dns_segments_buf[flow->packet.packet_direction]);
	
	if (dns_segments_buf->buffer==NULL) return 1;	// proceeds without buffer

	flow->packet.payload= &dns_segments_buf->buffer[*ploff];
	flow->packet.payload_packet_len= dns_segments_buf->buffer_used - *ploff;
	*ploff= 0;
	DBGINFO("set packet payload as p:%p (len:%u bytes); offs:%d; rec:%u; exp:%u",	flow->packet.payload,flow->packet.payload_packet_len,*ploff, dns_segments_buf->buffer_used,dns_segments_buf->max_expected)

	return (dns_segments_buf->buffer_used>=dns_segments_buf->max_expected);
}

/* *********************************************** */

static void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	int payload_offset;
	u_int8_t is_query, is_tcp=0,tempValue=1;
	u_int16_t s_port = 0, d_port = 0;

	// init the temp variables
	oldPayload=NULL;
	oldPayloadLen= 0;

  	NDPI_LOG_DBG(ndpi_struct, "search DNS in payload of: %u bytes\n",flow->packet.payload_packet_len);
	DBGTRACER("search DNS in payload %p of %u bytes",flow->packet.payload, flow->packet.payload_packet_len)

	if (flow->packet.payload_packet_len==0) 
		return;

	if(flow->packet.udp != NULL) {
		s_port = ntohs(flow->packet.udp->source);
		d_port = ntohs(flow->packet.udp->dest);
		payload_offset = 0;
	} else if(flow->packet.tcp != NULL) /* pkt size > 512 bytes */ {
		s_port = ntohs(flow->packet.tcp->source);
		d_port = ntohs(flow->packet.tcp->dest);
		payload_offset = 2;	// skip the bytes of length
		is_tcp=1;		
	} else {
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
		return;
	}

  	DBGTRACER("s:%u - d:%u -> payload len: %u",s_port,d_port,flow->packet.payload_packet_len)
  
  	if ((s_port == DNS_PORT) || (d_port == DNS_PORT) 
	  	|| (s_port == MDNS_PORT) || (d_port == MDNS_PORT) 
		|| (d_port == LLMNR_PORT)) {
	  
		// concatene the segments, if not retrasmission ---------
		if ( is_tcp && !flow->packet.tcp_retransmission ) {
			ndpi_search_dns_tcp_memory(ndpi_struct, flow);  
		} 
		else if (is_tcp) {
			DBGINFO("ALERT: retrasmission! stop processing this packet.")
			return;
		}

		// save and swap the pointer to buffer, instead of packet received bytes
		if (is_tcp ) {
			savePacketPayload(flow, payload_offset);
	
			tempValue= swap_packet_ref(flow, &payload_offset);
			DBGTRACER("swapped! ret value=%d; %d ? %lu", tempValue,flow->packet.payload_packet_len,(sizeof(struct ndpi_dns_packet_header)+payload_offset))
		}
		
		// ------------------------------------------------------

		if ( tempValue // perhaps, not yet received all expected bytes...
			  && flow->packet.payload_packet_len >= sizeof(struct ndpi_dns_packet_header)+payload_offset) {
			
			struct ndpi_dns_packet_header dns_header;
			int j = 0, max_len, off;
			
			int invalid = search_valid_dns(ndpi_struct, flow, &dns_header, payload_offset, &is_query);
			DBGTRACER("check for invalid result=%d", invalid)
			
			ndpi_protocol ret;

			ret.master_protocol   = NDPI_PROTOCOL_UNKNOWN;
			ret.app_protocol      = (d_port == LLMNR_PORT) ? NDPI_PROTOCOL_LLMNR : ((d_port == MDNS_PORT) ? NDPI_PROTOCOL_MDNS : NDPI_PROTOCOL_DNS);

			if(invalid) {
				// restore packet pointers and free buffer
				if ( is_tcp) restorePacketPayload(flow, &payload_offset, 1);
				
				DBGINFO("invalid protocol: esclude DNS from flow")
				
				// because of checking every time all buffer, whether invalid exclude it from flow
				NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
				return;
			}

				/* extract host name server from 'question section' */
			max_len = sizeof(flow->host_server_name)-1;
			off = sizeof(struct ndpi_dns_packet_header) + payload_offset;
			
#ifdef __DNS_H__
			DBGTRACER("host_server_name max len: %d, offset: %u", max_len, off)
			memset(flow->host_server_name,0,max_len);
			parseDnsName( flow->host_server_name, max_len, (int*)&off, flow->packet.payload, flow->packet.payload_packet_len );	
			j = strlen((const char*)flow->host_server_name);

			DBGINFO("host_server_name len: %d, [%s]", j, flow->host_server_name)
#else
/* Before continuing let's dissect the following queries to see if they are valid */
    for(idx=off, num_queries=0; (num_queries < dns_header.num_queries) && (idx < flow->packet.payload_packet_len);) {
      u_int8_t name_len = flow->packet.payload[idx];

#ifdef DNS_DEBUG
      printf("[DNS] [name_len: %u]\n", name_len);
#endif

      if(name_len == 0) {
		/* End of query */
		num_queries++;
		idx += 5;
		continue;
      }

      if((name_len+idx) >= flow->packet.payload_packet_len) {
	/* Invalid */
#ifdef DNS_DEBUG
		printf("[DNS] Invalid query len [%u >= %u]\n",
			(name_len+idx),
	    	flow->packet.payload_packet_len);
#endif
		NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
			break;
      	} else
			idx += name_len+1;
      	}			
		while(j < max_len && off < flow->packet.payload_packet_len && flow->packet.payload[off] != '\0') {
			uint8_t cl = flow->packet.payload[off++];	//init label counter

			if( (cl & 0xc0) != 0 || // we not support compressed names in query
					off + cl  >= flow->packet.payload_packet_len) {
				j = 0;	
				break;
			}

			if(j && j < max_len) flow->host_server_name[j++] = '.';	// replace the label length with dot, except the at first 

			while(j < max_len && cl != 0) {
				uint8_t c;
				u_int32_t shift;
				
				c = flow->packet.payload[off++];
				shift = ((u_int32_t) 1) << (c & 0x1f);
				flow->host_server_name[j++] = tolower((dns_validchar[c >> 5] & shift) ? c : '_');
				cl--;
			}
		}

		flow->host_server_name[j] = '\0';	
#endif	
			
			if(j > 0) {
				ndpi_protocol_match_result ret_match;

				/* check for domain generation algorithm using */
				ndpi_check_dga_name(ndpi_struct, flow, (char*)flow->host_server_name,1);
				
				ret.app_protocol = ndpi_match_host_subprotocol(ndpi_struct, flow,
										(char *)flow->host_server_name,
										strlen((const char*)flow->host_server_name),
										&ret_match,
										NDPI_PROTOCOL_DNS);

				if(ret_match.protocol_category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
					flow->category = ret_match.protocol_category;

				if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN)
					ret.master_protocol = checkDNSSubprotocol(s_port, d_port);
				else
					ret.master_protocol = NDPI_PROTOCOL_DNS;
				
				DBGINFO("protocol: %u/%u",ret.master_protocol,ret.app_protocol)
			}

			/* Report if this is a DNS query or reply */
			flow->protos.dns.is_query = is_query;
			
			flow->protos.dns.num_queries = (u_int8_t)dns_header.num_queries;	// always set!
			
			if(is_query) {
				//flow->protos.dns.dns_request_complete=1;
				/* In this case we say that the protocol has been detected just to let apps carry on with their activities */
				ndpi_set_detected_protocol(ndpi_struct, flow, ret.app_protocol, ret.master_protocol);

				/* This is necessary to inform the core to call this dissector again */
				flow->check_extra_packets = 1;

				/* Don't use just 1 as in TCP DNS more packets could be returned (e.g. ACK). */
				flow->max_extra_packets_to_check = 5;
				flow->extra_packets_func = search_dns_again;

				DBGINFO("-> returning from query, waiting for answer...")
				return; /* The response will set the verdict */
			}

			flow->protos.dns.num_answers = (u_int8_t) (dns_header.num_answers + dns_header.authority_rrs + dns_header.additional_rrs);
		
#ifdef DNS_DEBUG
			NDPI_LOG_DBG2(ndpi_struct, "[num_queries=%d][num_answers=%d][reply_code=%u][rsp_type=%u][host_server_name=%s]\n",
				flow->protos.dns.num_queries, flow->protos.dns.num_answers,
				flow->protos.dns.reply_code, flow->protos.dns.rsp_type, flow->host_server_name
				);
#endif
			DBGINFO("detected prot: %d.%d", flow->packet.detected_protocol_stack[1],flow->packet.detected_protocol_stack[0])
			if(flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
				/**
				 Do not set the protocol with DNS if ndpi_match_host_subprotocol() has
				matched a subprotocol
				**/
				NDPI_LOG_INFO(ndpi_struct, "found DNS\n");
				ndpi_set_detected_protocol(ndpi_struct, flow, ret.app_protocol, ret.master_protocol);
			} else {
				if((flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_DNS)
					|| (flow->packet.detected_protocol_stack[1] == NDPI_PROTOCOL_DNS)) {					
					// flow is ok, buffer contains all data, 
					// but do not free packet payload because it is managed in other part
				} else {
					// restore packet pointers and free buffer
					clear_all_dns_list(flow);
					if ( is_tcp) restorePacketPayload(flow, &payload_offset, 1);					
					NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
				}
			}
	 	}

		// restore packet pointers for other dissectors
		if ( is_tcp) {
			restorePacketPayload(flow, &payload_offset, 0);
			DBGTRACER("restorePacketPayload...")
		}
  	}


	// but require other processing
  	flow->check_extra_packets = 1;

	/* Don't use just 1 as in TCP DNS more packets could be returned (e.g. ACK). */
	flow->max_extra_packets_to_check = 15;
	flow->extra_packets_func = search_dns_again;

	DBGTRACER("exiting... ")
}

void init_dns_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("DNS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DNS,
				      ndpi_search_dns,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
