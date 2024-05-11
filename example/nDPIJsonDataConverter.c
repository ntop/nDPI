#include "nDPIJsonDataConverter.h"
#include "ndpi_typedefs.h"
#include "../json-c/include/json-c/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRUE 1
#define FALSE 0
#define RANDOM_UNINTIALIZED_NUMBER_VALUE -84742891
// Define the structure for ndpiData
struct NDPI_Risk
{
    int key;
    char* risk;
    char* severity;
    struct {
        int total;
        int client;
        int server;
    } risk_score;
};

struct NDPI_Confidence
{
    int key;
    char* value;
};

struct NDPI_tls
{
    char* version;
    char* server_names;
    char* ja3;
    char* ja3s;
    char* cipher;
    char* issuerDN;
    char* subjectDN;
};

struct Xfer_Packets
{
    unsigned int packets;
    unsigned int bytes;
};

struct Root_xfer
{
    struct Xfer_Packets source;
    struct Xfer_Packets destination;
};

struct Root_data
{
    char* src_ip;
    char* src_port;
    char* dest_ip;
    char* dst_port;
    char* l3_proto;
    char* l4_proto;
    int ip;
    char* proto;
    char* breed;
    int flow_id;
    char* event_start;
    char* event_end;
    char* event_duration;
    struct Root_xfer xfer;
    char* hostname;
};

struct NDPI_Data
{
    struct NDPI_Risk* flow_risk;
    size_t flow_risk_count;
    struct NDPI_Confidence confidence;
    char* confidence_value;
    struct NDPI_tls tls;
    char* proto_id;
    char* proto_by_ip;
    int proto_by_ip_id;
    int encrypted;
    int category_id;
    char* category;
};

static const char* ndpi_risk2description(ndpi_risk_enum risk)
{

    switch (risk) {
    case NDPI_URL_POSSIBLE_XSS:
        return("HTTP only: this risk indicates a possible `XSS (Cross Side Scripting) <https://en.wikipedia.org/wiki/Cross-site_scripting>`_ attack.");

    case NDPI_URL_POSSIBLE_SQL_INJECTION:
        return("HTTP only: this risk indicates a possible `SQL Injection attack <https://en.wikipedia.org/wiki/SQL_injection>`_.");

    case NDPI_URL_POSSIBLE_RCE_INJECTION:
        return("HTTP only: this risk indicates a possible `RCE (Remote Code Execution) attack <https://en.wikipedia.org/wiki/Arbitrary_code_execution>`_.");

    case NDPI_BINARY_APPLICATION_TRANSFER:
        return("HTTP only: this risk indicates that a binary application is downloaded/uploaded. Detected applications include Windows binaries, Linux executables, Unix scripts and Android apps.");

    case NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT:
        return("This risk indicates a known protocol used on a non standard port. Example HTTP is supposed to use TCP/80, and in case it is detected on TCP/1234 this risk is detected.");

    case NDPI_TLS_SELFSIGNED_CERTIFICATE:
        return("TLS/QUIC only: this risk is triggered when a `self-signed certificate <https://en.wikipedia.org/wiki/Self-signed_certificate>`_ is used.");

    case NDPI_TLS_OBSOLETE_VERSION:
        return("Risk triggered when TLS version is older than 1.1.");

    case NDPI_TLS_WEAK_CIPHER:
        return("Risk triggered when an unsafe TLS cipher is used. See `this page <https://community.qualys.com/thread/18212-how-does-qualys-determine-the-server-cipher-suites>`_ for a list of insecure ciphers.");

    case NDPI_TLS_CERTIFICATE_EXPIRED:
        return("Risk triggered when a TLS certificate is expired, i.e. the current date falls outside of the certificate validity dates.");

    case NDPI_TLS_CERTIFICATE_MISMATCH:
        return("Risk triggered when a TLS certificate does not match the hostname we're accessing. Example you do http://www.aaa.com and the TLS certificate returned is for www.bbb.com.");

    case NDPI_HTTP_SUSPICIOUS_USER_AGENT:
        return("HTTP only: this risk is triggered whenever the user agent contains suspicious characters or its format is suspicious. Example: <?php something ?> is a typical suspicious user agent.");

    case NDPI_NUMERIC_IP_HOST:
        return("This risk is triggered whenever a HTTP/TLS/QUIC connection is using a literal IPv4 or IPv6 address as ServerName (TLS/QUIC; example: SNI=1.2.3.4) or as Hostname (HTTP; example: http://1.2.3.4.).");

    case NDPI_HTTP_SUSPICIOUS_URL:
        return("HTTP only: this risk is triggered whenever the accessed URL is suspicious. Example: http://127.0.0.1/msadc/..%255c../..%255c../..%255c../winnt/system32/cmd.exe.");

    case NDPI_HTTP_SUSPICIOUS_HEADER:
        return("HTTP only: this risk is triggered whenever the HTTP peader contains suspicious entries such as Uuid, TLS_version, Osname that are unexpected on the HTTP header.");

    case NDPI_TLS_NOT_CARRYING_HTTPS:
        return("TLS only: this risk indicates that this TLS flow will not be used to transport HTTP content. Example VPNs use TLS to encrypt data rather to carry HTTP. This is useful to spot this type of cases.");

    case NDPI_SUSPICIOUS_DGA_DOMAIN:
        return("A `DGA <https://en.wikipedia.org/wiki/Domain_generation_algorithm>`_ is used to generate domain names often used by malwares. This risk indicates that this domain name can (but it's not 100% sure) a DGA as its name is suspicious.");

    case NDPI_MALFORMED_PACKET:
        return("This risk is generated when a packet (e.g. a DNS packet) has an unexpected formt. This can indicate a protocol error or more often an attempt to jeopardize a valid protocol to carry other type of data.");

    case NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER:
        return("This risk is generated whenever a SSH client uses an obsolete SSH protocol version or insecure ciphers.");

    case NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER:
        return("This risk is generated whenever a SSH server uses an obsolete SSH protocol version or insecure ciphers.");

    case NDPI_SMB_INSECURE_VERSION:
        return("This risk indicates that the `SMB <https://en.wikipedia.org/wiki/Server_Message_Block>`_ version used is insecure (i.e. v1).");

    case NDPI_TLS_SUSPICIOUS_ESNI_USAGE:
        return("`SNI <https://en.wikipedia.org/wiki/Server_Name_Indication>`_ is a way to carry in TLS the host/domain name we're accessing. ESNI means encrypted SNI and it is a way to mask SNI (carried in clear text in the TLS header) with encryption. While this practice is legal, it could be used for hiding data or for attacks such as a suspicious `domain fronting <https://github.com/SixGenInc/Noctilucent/blob/master/docs/>`_.");

    case NDPI_UNSAFE_PROTOCOL:
        return("This risk indicates that the protocol used is insecure and that a secure protocol should be used (e.g. Telnet vs SSH).");

    case NDPI_DNS_SUSPICIOUS_TRAFFIC:
        return("This risk is returned when DNS traffic returns an unexpected/obsolete `record type <https://en.wikipedia.org/wiki/List_of_DNS_record_types>`_."); /* Exfiltration ? */

    case NDPI_TLS_MISSING_SNI:
        return("TLS needs to carry the the `SNI <https://en.wikipedia.org/wiki/Server_Name_Indication>`_ of the remote server we're accessing. Unfortunately SNI is optional in TLS so it can be omitted. In this case this risk is triggered as this is a non-standard situation that indicates a potential security problem or a protocol using TLS for other purposes (or a protocol bug).");

    case NDPI_HTTP_SUSPICIOUS_CONTENT:
        return("HTTP only: risk reported when HTTP carries content in expected format. Example the HTTP header indicates that the context is text/html but the real content is not readeable (i.e. it can transport binary data). In general this is an attempt to use a valid MIME type to carry data that does not match the type.");

    case NDPI_RISKY_ASN:
        return("This is a placeholder for traffic exchanged with `ASN <https://en.wikipedia.org/wiki/Autonomous_system_(Internet)>`_ that are considered risky. nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).");

    case NDPI_RISKY_DOMAIN:
        return("This is a placeholder for traffic exchanged with domain names that are considered risky. nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).");

    case NDPI_MALICIOUS_JA3:
        return("`JA3 <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`_ is a method to fingerprint TLS traffic. This risk indicates that the JA3 of the TLS connection is considered suspicious (i.e. it has been found in known malware JA3 blacklists). nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).");

    case NDPI_MALICIOUS_SHA1_CERTIFICATE:
        return("TLS certificates are uniquely identified with a `SHA1 <https://en.wikipedia.org/wiki/SHA-1>`_ hash value. If such hash is found on a blacklist, this risk can be used. As for other risks, this is a placeholder as nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).");

    case NDPI_DESKTOP_OR_FILE_SHARING_SESSION:
        return("This risk is set when the flow carries desktop or file sharing sessions (e.g. TeamViewer or AnyDesk just to mention two).");

    case NDPI_TLS_UNCOMMON_ALPN:
        return("This risk is set when the `ALPN <https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation>`_ (it indicates the protocol carried into this TLS flow, for instance HTTP/1.1) is uncommon with respect to the list of expected values");

    case NDPI_TLS_CERT_VALIDITY_TOO_LONG:
        return("From 01/09/2020 TLS certificates lifespan is limited to `13 months <https://www.appviewx.com/blogs/tls-certificate-lifespans-now-capped-at-13-months/>`_. This risk is triggered for certificates not respecting this directive.");

    case NDPI_TLS_SUSPICIOUS_EXTENSION:
        return("This risk is triggered when the domain name (SNI extension) is not printable and thus it is a problem. In TLS extensions can be dynamically specified by the client in the hello packet.");

    case NDPI_TLS_FATAL_ALERT:
        return("This risk is triggered when a TLS fatal alert is detected in the TLS flow. See `this page <https://techcommunity.microsoft.com/t5/iis-support-blog/ssl-tls-alert-protocol-and-the-alert-codes/ba-p/377132>`_ for details.");

    case NDPI_SUSPICIOUS_ENTROPY:
        return("This risk is used to detect suspicious data carried in ICMP packets whose entropy (used to measure how data is distributed, hence to indirectly guess the type of data carried on) is suspicious and thus that it can indicate a data leak. Suspicious values indicate random entropy or entropy that is similar to encrypted traffic. In the latter case, this can be a suspicious data exfiltration symptom.");

    case NDPI_CLEAR_TEXT_CREDENTIALS:
        return("Clear text protocols are not bad per-se, but they should be avoided when they carry credentials as they can be intercepted by malicious users. This risk is triggered whenever clear text protocols (e.g. FTP, HTTP, IMAP...) contain credentials in clear text (read it as nDPI does not trigger this risk for HTTP connections that do not carry credentials).");

    case NDPI_DNS_LARGE_PACKET:
        return("`DNS <https://en.wikipedia.org/wiki/Domain_Name_System>`_ packets over UDP should be limited to 512 bytes. DNS packets over this threshold indicate a potential security risk (e.g. use DNS to carry data) or a misconfiguration.");

    case NDPI_DNS_FRAGMENTED:
        return("UDP `DNS <https://en.wikipedia.org/wiki/Domain_Name_System>`_ packets cannot be fragmented. If so, this indicates a potential security risk (e.g. use DNS to carry data) or a misconfiguration.");

    case NDPI_INVALID_CHARACTERS:
        return("The risk is set whenever a dissected protocol contains characters not allowed in that protocol field. For example a DNS hostname must only contain a subset of all printable characters or else this risk is set. Additionally, some TLS protocol fields are checked for printable characters as well.");

    case NDPI_POSSIBLE_EXPLOIT:
        return("The risk is set whenever a possible exploit (e.g. `Log4J/Log4Shell <https://en.wikipedia.org/wiki/Log4Shell>`_) is detected.");

    case NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE:
        return("The risk is set whenever a TLS certificate is close to the expiration date.");

    case NDPI_PUNYCODE_IDN:
        return("The risk is set whenever a domain name is specified in IDN format as they are sometimes used in `IDN homograph attacks <https://en.wikipedia.org/wiki/IDN_homograph_attack>`_.");

    case NDPI_ERROR_CODE_DETECTED:
        return("The risk is set whenever an error code is detected in the underlying protocol (e.g. HTTP and DNS).");

    case NDPI_HTTP_CRAWLER_BOT:
        return("The risk is set whenever a crawler/bot/robot has been detected");

    case NDPI_ANONYMOUS_SUBSCRIBER:
        return("The risk is set whenever the (source) ip address has been anonymized and it can't be used to identify the subscriber. Example: the flow is generated by an iCloud - private - relay exit node.");

    case NDPI_UNIDIRECTIONAL_TRAFFIC:
        return("The risk is set whenever the flow has unidirectional traffic (typically no traffic on the server to client direction). This risk is not triggered for multicast / broadcast destinations.");

    case NDPI_HTTP_OBSOLETE_SERVER:
        return("This risk is generated whenever a HTTP server uses an obsolete HTTP server version.");

    case NDPI_PERIODIC_FLOW:
        return("This risk is generated whenever a flow is observed at a specific periodic pace (e.g. every 10 seconds).");

    case NDPI_MINOR_ISSUES:
        return("Minor packet/flow issues (e.g. DNS traffic with zero TTL) have been detected.");

    case NDPI_TCP_ISSUES:
        return("Relevant TCP connection issues such as connection refused, scan, or probe attempt.");

    default:

        return("ERROR: Unknown Risk");
    }
}


/*--------------------------------------------------------------------------------------------------------------------------------------------------------*/

// Function to convert ndpi field to the desired structure
struct NDPI_Data getnDPIStructure(const char* ndpiJson)
{
    struct NDPI_Data result;
    result.flow_risk = NULL;
    result.flow_risk_count = 0;
    result.confidence.key = RANDOM_UNINTIALIZED_NUMBER_VALUE;
    result.confidence.value = NULL;
    result.tls.version = NULL;
    result.tls.server_names = NULL;
    result.tls.ja3 = NULL;
    result.tls.ja3s = NULL;
    result.tls.cipher = NULL;
    result.tls.issuerDN = NULL;
    result.tls.subjectDN = NULL;

    result.confidence_value = NULL;
    result.proto_id = NULL;
    result.proto_by_ip = NULL;
    result.proto_by_ip_id = RANDOM_UNINTIALIZED_NUMBER_VALUE;
    result.encrypted = RANDOM_UNINTIALIZED_NUMBER_VALUE;
    result.category_id = 84742891;
    result.category = NULL;

    // Parse JSON string
    json_object* root = json_tokener_parse(ndpiJson);
    if (root == NULL)
    {
        fprintf(stderr, "Error parsing JSON\n");
        return result;
    }

    json_object* ndpiObject;
    if (json_object_object_get_ex(root, "ndpi", &ndpiObject))
    {
        // Extract flow_risk array
        json_object* flowRiskObj = NULL;
        if (json_object_object_get_ex(ndpiObject, "flow_risk", &flowRiskObj) && json_object_is_type(flowRiskObj, json_type_object))
        {
            // Get the number of elements in the flow_risk object
            int flowRiskCount = json_object_object_length(flowRiskObj);

            // Allocate memory for NDPI_Risk array
            result.flow_risk = malloc(flowRiskCount * sizeof(struct NDPI_Risk));
            if (result.flow_risk == NULL) 
            {
                fprintf(stderr, "Memory allocation failed\n");
                return result;
            }

            // Initialize the count of flow_risk elements
            result.flow_risk_count = 0;

            // Iterate through each element of the flow_risk object
            json_object_object_foreach(flowRiskObj, key, val) 
            {
                json_object* riskObj = val;

                // Extract risk, severity, and risk_score objects
                json_object* risk;
                json_object* severity;
                json_object* riskScoreObj;
                if (json_object_object_get_ex(riskObj, "risk", &risk) &&
                    json_object_object_get_ex(riskObj, "severity", &severity) &&
                    json_object_object_get_ex(riskObj, "risk_score", &riskScoreObj))
                {

                    // Extract risk_score values
                    json_object* totalObj;
                    json_object* clientObj;
                    json_object* serverObj;
                    if (json_object_object_get_ex(riskScoreObj, "total", &totalObj) &&
                        json_object_object_get_ex(riskScoreObj, "client", &clientObj) &&
                        json_object_object_get_ex(riskScoreObj, "server", &serverObj))
                    {

                        // Allocate memory for the NDPI_Risk structure
                        result.flow_risk[result.flow_risk_count].risk = _strdup(json_object_get_string(risk));
                        result.flow_risk[result.flow_risk_count].severity = _strdup(json_object_get_string(severity));
                        result.flow_risk[result.flow_risk_count].risk_score.total = json_object_get_int(totalObj);
                        result.flow_risk[result.flow_risk_count].risk_score.client = json_object_get_int(clientObj);
                        result.flow_risk[result.flow_risk_count].risk_score.server = json_object_get_int(serverObj);
                        result.flow_risk[result.flow_risk_count].key = atoi(key);

                        // Increment the count of flow_risk elements
                        result.flow_risk_count++;
                    }
                }
            }
        }

        // Extract confidence object
        json_object* confidenceObj;
        if (json_object_object_get_ex(ndpiObject, "confidence", &confidenceObj) && json_object_is_type(confidenceObj, json_type_object))
        {
            // Extract key and value
            const char* keyStr = NULL;
            json_object_object_foreach(confidenceObj, key, val) 
            {
                keyStr = key;
                break; // Assuming there's only one key in confidence
            }
            json_object* value = json_object_object_get(confidenceObj, keyStr);

            // Store confidence data in the result
            result.confidence.key = atoi(keyStr);
            result.confidence.value = _strdup(json_object_get_string(value));
        }

        // Extract tls object
        json_object* tlsObject;
        if (json_object_object_get_ex(ndpiObject, "tls", &tlsObject) && json_object_is_type(tlsObject, json_type_object))
        {
            json_object* version_object;
            if (json_object_object_get_ex(tlsObject, "version", &version_object))
            {
                result.tls.version = _strdup(json_object_get_string(version_object));
            }

            json_object* server_names_object;
            if (json_object_object_get_ex(tlsObject, "server_names", &server_names_object))
            {
                result.tls.server_names = _strdup(json_object_get_string(server_names_object));
            }

            json_object* ja3_object;
            if (json_object_object_get_ex(tlsObject, "ja3", &ja3_object))
            {
                result.tls.ja3 = _strdup(json_object_get_string(ja3_object));
            }

            json_object* ja3s_object;
            if (json_object_object_get_ex(tlsObject, "ja3s", &ja3s_object))
            {
                result.tls.ja3s = _strdup(json_object_get_string(ja3s_object));
            }

            json_object* cipher_object;
            if (json_object_object_get_ex(tlsObject, "cipher", &cipher_object))
            {
                result.tls.cipher = _strdup(json_object_get_string(cipher_object));
            }

            json_object* issuerDN_object;
            if (json_object_object_get_ex(tlsObject, "issuerDN", &issuerDN_object))
            {
                result.tls.issuerDN = _strdup(json_object_get_string(issuerDN_object));
            }

            json_object* subjectDN_object;
            if (json_object_object_get_ex(tlsObject, "subjectDN", &subjectDN_object))
            {
                result.tls.subjectDN = _strdup(json_object_get_string(subjectDN_object));
            }
           
        }

        // Extract rest of ndpi data
        json_object* proto_id;
        if (json_object_object_get_ex(ndpiObject, "proto_id", &proto_id))
        {
            result.proto_id = _strdup(json_object_get_string(proto_id));
        }
       
        json_object* proto_by_ip;
        if (json_object_object_get_ex(ndpiObject, "proto_by_ip", &proto_by_ip))
        {
            result.proto_by_ip = _strdup(json_object_get_string(proto_by_ip));
        }

        json_object* proto_by_ip_id;
        if (json_object_object_get_ex(ndpiObject, "proto_by_ip_id", &proto_by_ip_id))
        {
            result.proto_by_ip_id = json_object_get_int(proto_by_ip_id);
        }

        json_object* encrypted;
        if (json_object_object_get_ex(ndpiObject, "encrypted", &encrypted))
        {
            result.encrypted = json_object_get_int(encrypted);
        }

        json_object* category_id;
        if (json_object_object_get_ex(ndpiObject, "category_id", &category_id))
        {
            result.category_id = json_object_get_int(category_id);
        }

        json_object* category;
        if (json_object_object_get_ex(ndpiObject, "category", &category))
        {
            result.category = _strdup(json_object_get_string(category));
        }
    }

    json_object_put(root);

    return result;
}

static struct Root_data getRootDataStructure(const char* originalJsonStr)
{
    struct Root_data result;
    result.src_ip = NULL;
    result.src_port = NULL;
    result.dest_ip = NULL;
    result.dst_port = NULL;
    result.l3_proto = NULL;
    result.ip = RANDOM_UNINTIALIZED_NUMBER_VALUE;
    result.l4_proto = NULL;
    result.proto = NULL;
    result.breed = NULL;
    result.flow_id = RANDOM_UNINTIALIZED_NUMBER_VALUE;
    result.event_start = NULL;
    result.event_end = NULL;
    result.event_duration = NULL;
    result.xfer.source.bytes = RANDOM_UNINTIALIZED_NUMBER_VALUE;
    result.xfer.source.packets = RANDOM_UNINTIALIZED_NUMBER_VALUE;
    result.xfer.destination.bytes = RANDOM_UNINTIALIZED_NUMBER_VALUE;
    result.xfer.destination.packets = RANDOM_UNINTIALIZED_NUMBER_VALUE;
    result.hostname = NULL;

    // Parse JSON string
    json_object* root = json_tokener_parse(originalJsonStr);
    if (root == NULL)
    {
        fprintf(stderr, "Error parsing JSON\n");
        return result;
    }

    // src_ip and src_port data
    json_object* src_ip;
    if (json_object_object_get_ex(root, "src_ip", &src_ip))
    {
        result.src_ip = _strdup(json_object_get_string(src_ip));
    }
    

    json_object* src_port;
    if (json_object_object_get_ex(root, "src_port", &src_port))
    {
        result.src_port = _strdup(json_object_get_string(src_port));
    }
    

    // dest_ip and dst_port data
    json_object* dest_ip;
    if (json_object_object_get_ex(root, "dest_ip", &dest_ip))
    {
        result.dest_ip = _strdup(json_object_get_string(dest_ip));
    }
    

    json_object* dst_port;
    if (json_object_object_get_ex(root, "dst_port", &dst_port))
    {
        result.dst_port = _strdup(json_object_get_string(dst_port));
    }
    
    // network object
    json_object* l3_proto;
    if (json_object_object_get_ex(root, "l3_proto", &l3_proto))
    {
        result.l3_proto = _strdup(json_object_get_string(l3_proto));
    }

    json_object* ip;
    if (json_object_object_get_ex(root, "ip", &ip))
    {
        result.ip = json_object_get_int(ip);
    }
   

    json_object* l4_proto;
    if (json_object_object_get_ex(root, "l4_proto", &l4_proto))
    {
        result.l4_proto = _strdup(json_object_get_string(l4_proto));
    }
   
    json_object* proto;
    if (json_object_object_get_ex(root, "proto", &proto))
    {
        result.proto = _strdup(json_object_get_string(proto));
    }
    

    json_object* ndpi_object;
    if (json_object_object_get_ex(root, "ndpi", &ndpi_object))
    {
        json_object* breed;
        if (json_object_object_get_ex(ndpi_object, "breed", &breed))
        {
            result.breed = _strdup(json_object_get_string(breed));
        }

        json_object* hostname;
        if (json_object_object_get_ex(ndpi_object, "hostname", &hostname))
        {
            result.hostname = _strdup(json_object_get_string(hostname));
        }
    }
    

    json_object* flow_id;
    if (json_object_object_get_ex(root, "flow_id", &flow_id))
    {
        result.flow_id = json_object_get_int(flow_id);
    }
  
    // event
    json_object* event_object;
    if (json_object_object_get_ex(root, "event", &event_object))
    {
        json_object* event_start;
        if (json_object_object_get_ex(event_object, "start", &event_start))
        {
            result.event_start = _strdup(json_object_get_string(event_start));
        }

        json_object* event_end;
        if (json_object_object_get_ex(event_object, "end", &event_end))
        {
            result.event_end = _strdup(json_object_get_string(event_end));
        }

        json_object* event_duration;
        if (json_object_object_get_ex(event_object, "duration", &event_duration))
        {
            result.event_duration = _strdup(json_object_get_string(event_duration));
        }
    }


    // xfer
    json_object* xfer_object;
    if (json_object_object_get_ex(root, "xfer", &xfer_object))
    {
        json_object* src2dst_packets;
        if (json_object_object_get_ex(xfer_object, "src2dst_packets", &src2dst_packets))
        {
            result.xfer.source.packets = json_object_get_int(src2dst_packets);
        }

        json_object* src2dst_bytes;
        if (json_object_object_get_ex(xfer_object, "src2dst_bytes", &src2dst_bytes))
        {
            result.xfer.source.bytes = json_object_get_int(src2dst_bytes);
        }

        json_object* dst2src_packets;
        if (json_object_object_get_ex(xfer_object, "dst2src_packets", &dst2src_packets))
        {
            result.xfer.destination.packets = json_object_get_int(dst2src_packets);
        }

        json_object* dst2src_bytes;
        if (json_object_object_get_ex(xfer_object, "dst2src_bytes", &dst2src_bytes))
        {
            result.xfer.destination.bytes = json_object_get_int(dst2src_bytes);
        }
    }

    json_object_put(root);

    return result;
}

static char* create_nDPI_Json_String(const struct NDPI_Data* ndpi)
{
    // Create a new JSON object for ndpi
    //json_object* root = json_object_new_object();
    json_object* ndpiObj = json_object_new_object();

    // Serialize flow_risk
    json_object* flowRiskArray = json_object_new_array();
    for (size_t i = 0; i < ndpi->flow_risk_count; ++i) 
    {
        json_object* riskObj = json_object_new_object();
        json_object_object_add(riskObj, "key", json_object_new_int(ndpi->flow_risk[i].key));
        json_object_object_add(riskObj, "description", json_object_new_string(ndpi_risk2description((ndpi_risk_enum)ndpi->flow_risk[i].key)));
        json_object_object_add(riskObj, "risk", json_object_new_string(ndpi->flow_risk[i].risk));
        json_object_object_add(riskObj, "severity", json_object_new_string(ndpi->flow_risk[i].severity));

        json_object* riskScoreObj = json_object_new_object();
        json_object_object_add(riskScoreObj, "total", json_object_new_int(ndpi->flow_risk[i].risk_score.total));
        json_object_object_add(riskScoreObj, "client", json_object_new_int(ndpi->flow_risk[i].risk_score.client));
        json_object_object_add(riskScoreObj, "server", json_object_new_int(ndpi->flow_risk[i].risk_score.server));
        json_object_object_add(riskObj, "risk_score", riskScoreObj);

        json_object_array_add(flowRiskArray, riskObj);
    }

    if (ndpi->flow_risk_count > 0)
    {
        json_object_object_add(ndpiObj, "flow_risk", flowRiskArray);        
    }
    else
    {
        json_object_put(flowRiskArray);
    }

    //  Serialize confidence
    if (ndpi->confidence.value != NULL)
    {
        json_object* confidenceObj = json_object_new_object();
        json_object_object_add(confidenceObj, "key", json_object_new_int(ndpi->confidence.key));
        json_object_object_add(confidenceObj, "value", json_object_new_string(ndpi->confidence.value));       
        json_object_object_add(ndpiObj, "confidence", confidenceObj);       
    }

    // Serialize tls
    bool addTLS = FALSE;
    json_object* tlsObj = json_object_new_object();
    if (ndpi->tls.version != NULL)
    {
        json_object_object_add(tlsObj, "version", json_object_new_string(ndpi->tls.version));
        addTLS = TRUE;
    }

   
    bool addClient = FALSE;

    json_object* client = json_object_new_object();
    if (ndpi->tls.server_names != NULL)
    {
        json_object_object_add(client, "server_name", json_object_new_string(ndpi->tls.server_names));
        addClient = TRUE;
        
    }

    if (ndpi->tls.ja3 != NULL)
    {
        json_object_object_add(client, "ja3", json_object_new_string(ndpi->tls.ja3));
        addClient = TRUE;     
    }

    if (addClient)
    {
        json_object_object_add(tlsObj, "client", client);
        addTLS = TRUE;
    }
    else
    {
        json_object_put(client);
    }

    json_object* server = json_object_new_object();
    bool addServer = FALSE;
    if (ndpi->tls.ja3s != NULL)
    {
        json_object_object_add(server, "ja3", json_object_new_string(ndpi->tls.ja3s));        
        addServer = TRUE;
    }


    if (ndpi->tls.issuerDN != NULL)
    {
        json_object_object_add(server, "issuer", json_object_new_string(ndpi->tls.issuerDN));      
        addServer = TRUE;
    }

    if (ndpi->tls.subjectDN != NULL)
    {
        json_object_object_add(server, "subject", json_object_new_string(ndpi->tls.subjectDN));
        addServer = TRUE;
    }


    if (addServer)
    {
        json_object_object_add(tlsObj, "server", server);
        addTLS = TRUE;
    }
    else
    {
        json_object_put(server);
    }


    if (ndpi->tls.cipher != NULL)
    {
        json_object_object_add(tlsObj, "cipher", json_object_new_string(ndpi->tls.cipher));
        addTLS = TRUE;
    }

    if (addTLS)
    {
        json_object_object_add(ndpiObj, "tls", tlsObj);
    }
    else
    {
        json_object_put(tlsObj);
    }


    //Serialize rest of data
    if (ndpi->proto_id != NULL)
    {
        json_object_object_add(ndpiObj, "proto_id", json_object_new_string(ndpi->proto_id));
    }

    if (ndpi->proto_by_ip != NULL)
    {
        json_object_object_add(ndpiObj, "proto_by_ip", json_object_new_string(ndpi->proto_by_ip) );
    }

    if (ndpi->proto_by_ip_id != RANDOM_UNINTIALIZED_NUMBER_VALUE)
    {
        json_object_object_add(ndpiObj, "proto_by_ip_id", json_object_new_int(ndpi->proto_by_ip_id));
    }

    if (ndpi->encrypted != RANDOM_UNINTIALIZED_NUMBER_VALUE)
    {
        json_object_object_add(ndpiObj, "encrypted", json_object_new_int(ndpi->encrypted));
    }

    if (ndpi->category_id != RANDOM_UNINTIALIZED_NUMBER_VALUE)
    {
        json_object_object_add(ndpiObj, "category_id", json_object_new_int(ndpi->category_id));
    }

    if (ndpi->category != NULL)
    {
        json_object_object_add(ndpiObj, "category", json_object_new_string(ndpi->category));
    }

    // Return the serialized JSON string
    char* jsonString = NULL;
    if (json_object_object_length(ndpiObj) > 0)
    {
        jsonString = _strdup(json_object_to_json_string(ndpiObj));
    }

   json_object_put(ndpiObj);
    
    // Return the serialized JSON string
    return jsonString;
}

// Function to free memory allocated for NDPI_Data
static void FreeConvertnDPIDataFormat(struct NDPI_Data* ndpiData)
{
    if (ndpiData == NULL) {
        return;
    }

    for (size_t i = 0; i < ndpiData->flow_risk_count; ++i) 
    {
        if (ndpiData->flow_risk[i].risk != NULL)
        {
            free(ndpiData->flow_risk[i].risk);
        }

        if (ndpiData->flow_risk[i].severity != NULL)
        {
            free(ndpiData->flow_risk[i].severity);
        }
    }

    if (ndpiData->flow_risk != NULL)
    {
        free(ndpiData->flow_risk);
    }

    if (ndpiData->confidence.value != NULL)
    {
        free(ndpiData->confidence.value);
    }

    if (ndpiData->tls.version != NULL)
    {
        free(ndpiData->tls.version);
    }

    if (ndpiData->tls.server_names != NULL)
    {
        free(ndpiData->tls.server_names);
    }

    if (ndpiData->tls.ja3 != NULL)
    {
        free(ndpiData->tls.ja3);
    }

    if (ndpiData->tls.ja3s != NULL)
    {
        free(ndpiData->tls.ja3s);
    }

    if (ndpiData->tls.cipher != NULL)
    {
        free(ndpiData->tls.cipher);
    }

    if (ndpiData->tls.subjectDN != NULL)
    {
        free(ndpiData->tls.subjectDN);
    }

    if (ndpiData->tls.issuerDN != NULL)
    {
        free(ndpiData->tls.issuerDN);
    }

    if (ndpiData->proto_id != NULL)
    {
        free(ndpiData->proto_id);
    }

    if (ndpiData->confidence_value != NULL)
    {
        free(ndpiData->confidence_value);
    }

    if (ndpiData->proto_by_ip != NULL)
    {
        free(ndpiData->proto_by_ip);
    }

    if (ndpiData->category != NULL)
    {
        free(ndpiData->category);
    }
}

static void FreeConvertRootDataFormat(struct Root_data* rootData)
{
    if (rootData == NULL) 
    {
        return;
    }

    if (rootData->src_ip != NULL)
    {
        free(rootData->src_ip);
    }

    if (rootData->src_port != NULL)
    {
        free(rootData->src_port);
    }

    if (rootData->dest_ip != NULL)
    {
        free(rootData->dest_ip);
    }

    if (rootData->dst_port != NULL)
    {
        free(rootData->dst_port);
    }

    if (rootData->l3_proto != NULL)
    {
        free(rootData->l3_proto);
    }

    if (rootData->l4_proto != NULL)
    {
        free(rootData->l4_proto);
    }

    if (rootData->proto != NULL)
    {
        free(rootData->proto);
    }


    if (rootData->breed != NULL)
    {
        free(rootData->breed);
    }

    if (rootData->event_start != NULL)
    {
        free(rootData->event_start);
    }

    if (rootData->event_end != NULL)
    {
        free(rootData->event_end);
    }

    if (rootData->event_duration != NULL)
    {
        free(rootData->event_duration);
    }

    if (rootData->hostname != NULL)
    {
        free(rootData->hostname);
    }

}

static void add_nDPI_Data(json_object** root_object, struct NDPI_Data nDPIStructure)
{
    char* nDPIJsonString = create_nDPI_Json_String(&nDPIStructure);
    if (nDPIJsonString == NULL)
    {
        fprintf(stderr, "Error parsing new ndpi JSON\n");
        return;
    }

    json_object* newNDPIObject = json_tokener_parse(nDPIJsonString);
    if (newNDPIObject == NULL)
    {
        fprintf(stderr, "Error parsing JSON string\n");
        free(nDPIJsonString); // Free allocated memory for JSON string
        return;
    }

    json_object_object_add(*root_object, "ndpi", newNDPIObject);
    free(nDPIJsonString); // Free allocated memory for JSON string if not needed anymore
}

/*--------------------------------------------------------------------------------------------------------------------------------------*/
static void add_Root_Data(json_object** root_object,  struct Root_data rootDataStructure, int flowRiskCount)
{
    json_object* src_object = json_object_new_object();

    bool addSrc = FALSE;
    if (rootDataStructure.src_ip != NULL)
    {
        json_object_object_add(src_object, "ip", json_object_new_string(rootDataStructure.src_ip));
        addSrc = TRUE;
    }

    if (rootDataStructure.src_port != NULL)
    {
        json_object_object_add(src_object, "port", json_object_new_string(rootDataStructure.src_port));
        addSrc = TRUE;
    }

    if (addSrc)
    {
        json_object_object_add(*root_object, "source", src_object);
    }

    bool addDest = FALSE;
    json_object* dest_object = json_object_new_object();

    if (rootDataStructure.dest_ip != NULL)
    {
        json_object_object_add(dest_object, "ip", json_object_new_string(rootDataStructure.dest_ip));
        addDest = TRUE;
    }

    if (rootDataStructure.dst_port != NULL)
    {
        json_object_object_add(dest_object, "port", json_object_new_string(rootDataStructure.dst_port));
        addDest = TRUE;
    }

    if (addDest)
    {
        json_object_object_add(*root_object, "destination", dest_object);
    }

    json_object* network_object = json_object_new_object();
    bool addNetwork = FALSE;

    if (rootDataStructure.ip != RANDOM_UNINTIALIZED_NUMBER_VALUE)
    {
        if (rootDataStructure.ip == 4)
        {
            json_object_object_add(network_object, "type", json_object_new_string("ipv4"));
            addNetwork = TRUE;
        }

        if (rootDataStructure.ip == 6)
        {
            json_object_object_add(network_object, "type", json_object_new_string("ipv6"));
            addNetwork = TRUE;
        }
    }

    if (rootDataStructure.l4_proto != NULL)
    {
        json_object_object_add(network_object, "transport", json_object_new_string(rootDataStructure.l4_proto));
        addNetwork = TRUE;
    }

    if (rootDataStructure.proto != NULL)
    {
        json_object_object_add(network_object, "application", json_object_new_string(rootDataStructure.proto));
        addNetwork = TRUE;
    }

    if (addNetwork)
    {
        json_object_object_add(*root_object, "network", network_object);
    }
   
    if (rootDataStructure.breed != NULL)
    {
        json_object* breed_object = json_object_new_object();
        json_object_object_add(breed_object, "category", json_object_new_string(rootDataStructure.breed));
        json_object_object_add(*root_object, "rule", breed_object);
    }

    // Event starts here

    json_object* event_object = json_object_new_object();
    bool addEvent = FALSE;

    if (rootDataStructure.event_start != NULL)
    {
        json_object_object_add(event_object, "start", json_object_new_string(rootDataStructure.event_start));
        addEvent = TRUE;
    }
    if (rootDataStructure.event_end != NULL)
    {
        json_object_object_add(event_object, "end", json_object_new_string(rootDataStructure.event_end));
        addEvent = TRUE;
    }

    if (rootDataStructure.event_duration != NULL)
    {
        json_object_object_add(event_object, "duration", json_object_new_string(rootDataStructure.event_duration));
        addEvent = TRUE;
    }

    if (addEvent)
    {
        json_object_object_add(*root_object, "event", event_object);
    }

    // Flow starts here
    if (rootDataStructure.flow_id != RANDOM_UNINTIALIZED_NUMBER_VALUE)
    {
        json_object* flow_id_object = json_object_new_object();
        json_object_object_add(flow_id_object, "id", json_object_new_int(rootDataStructure.flow_id));
        json_object_object_add(*root_object, "flow", flow_id_object);
    }

    // Xfer starts here

    json_object* xfer_object = json_object_new_object();
    bool addXfer = FALSE;
    if (rootDataStructure.xfer.source.packets != RANDOM_UNINTIALIZED_NUMBER_VALUE)
    {
        json_object* packets_object = json_object_new_object();
        json_object_object_add(packets_object, "packets", json_object_new_int(rootDataStructure.xfer.source.packets));
        json_object_object_add(packets_object, "bytes", json_object_new_int(rootDataStructure.xfer.source.bytes));
        json_object_object_add(xfer_object, "source", packets_object);
        addXfer = TRUE;
    }

    if (rootDataStructure.xfer.destination.packets != RANDOM_UNINTIALIZED_NUMBER_VALUE)
    {
        json_object* packets_object = json_object_new_object();
        json_object_object_add(packets_object, "packets", json_object_new_int(rootDataStructure.xfer.destination.packets));
        json_object_object_add(packets_object, "bytes", json_object_new_int(rootDataStructure.xfer.destination.bytes));
        json_object_object_add(xfer_object, "destination", packets_object);
        addXfer = TRUE;
    }

    if (addXfer)
    {
        json_object_object_add(*root_object, "xfer", xfer_object);
    }

    // hostname
    if (rootDataStructure.hostname != NULL)
    {
        json_object* full_object = json_object_new_object();
        json_object_object_add(full_object, "full", json_object_new_string(rootDataStructure.hostname));
        json_object_object_add(*root_object, "url", full_object);    
    }   

    if (flowRiskCount > 0)
    {
        json_object* event_object = json_object_new_object();
        json_object_object_add(event_object, "kind", json_object_new_string("alert"));
        json_object_object_add(*root_object, "event", event_object);
    }
    else
    {
		json_object* event_object = json_object_new_object();
		json_object_object_add(event_object, "kind", json_object_new_string("event"));
		json_object_object_add(*root_object, "event", event_object);        
    }
}

void ConvertnDPIDataFormat(char* originalJsonStr, char** converted_json_str, size_t* createAlert)
{
    struct NDPI_Data ndpiData = getnDPIStructure(originalJsonStr);
    *createAlert = ndpiData.flow_risk_count;

    json_object* root_object = json_object_new_object();
    add_nDPI_Data(&root_object, ndpiData);

    struct Root_data rootData = getRootDataStructure(originalJsonStr);
    add_Root_Data(&root_object, rootData, ndpiData.flow_risk_count);

    *converted_json_str = _strdup(json_object_to_json_string(root_object));

    FreeConvertnDPIDataFormat(&ndpiData);
    json_object_put(root_object);
    FreeConvertRootDataFormat(&rootData);
}

void DeletenDPIRisk(char* originalJsonStr, char** converted_json_str)
{
    json_object* root = json_tokener_parse(originalJsonStr);
    if (root == NULL)
    {
        fprintf(stderr, "Error parsing JSON\n");
        return;
    }

    json_object* ndpiObject;
    if (json_object_object_get_ex(root, "ndpi", &ndpiObject))
    {
        json_object_object_del(ndpiObject, "flow_risk");

        if (json_object_object_length(ndpiObject) < 1)
        {
            json_object_object_del(root, "ndpi");
        }       
    }


    json_object* eventObject;
    if (json_object_object_get_ex(root, "event", &eventObject))
    {
        json_object_object_del(eventObject, "kind");
        json_object_object_add(eventObject, "kind", json_object_new_string("event"));
    }

    *converted_json_str = strdup(json_object_to_json_string(root));
    json_object_put(root);

}



