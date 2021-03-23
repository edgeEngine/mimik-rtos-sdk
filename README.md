                          mimik RTOS client Sdk
                          =====================
NOTE: This mimik RTOS client sdk uses the following 3-party libraries shipped with esp32 
system:
- mbedtls 
- cJSON 

---------
Overview:
---------
mimik RTOS client SDK is a thin and an efficient client stub comprising of well
defined and a simple to use c library. It can aid an application running in a
tiny embedded device that is attached to a common network access point, to be
able to discover mimik edge cloud supernode acting as link local leader node.
After discovering an edge link local supernode, using minimal multicast mDNS
query, the client stub functions, then communicates with the supernode directly
and securely using https to obtain a list of available edge-microservices. Such
micro-services performing a specific task could then be delegated to an edge
processor say that does sensing.

In essence, mimik RTOS client stub SDK library functions, facilitates highly
secured and authenticated edge microservices discovery. It carries out
a multi-stage edge supernode and microservice discovery process in a linklocal
network, that the calling node has taken a common network residence with. 

In the first stage: 
It sends a very minimal -- but with encrypted unique verifiable node id --, a
mimik specific mDNS multicast query packet to the attached router.  The intent
is to solicit a response with a unicast reply from a participating edge super
node running in the same link local cluster attached to the same network access
point.

In the second stage:
Using the information obtained in stage 1 via mDNS, the RTOS client stub will
then directly interact with the supernode using https/TLS secured communication
with SSL client key and certificates. The intent of second stage is to securely
obtain a list of microservices available in link local cluster as JSON object
from the leader edge supernode.  

--------------------------
Source code organization:
--------------------------
mimik-rtos-sdk/include/ and mimik-rtos-sdk/src/ contains the following:
- mimik_edge_services.h and mimik_edge_services.c

  Main client mimik-rtos-sdk interface function to be used by applications.
  A single microservice discovery function and structures for applications
  to include and achieve edge microservice discovery.

- mk_mdns_client.h and mk_mdns_client.c
  Stage-1 mdns based supernode discovery functions used by mimik_edge_services.c
  This is more of a use to mimik_edge_services and not for end application users.

- mk_tls_https_request.h and mk_tls_https_request.c
  Stage-2 provides https/tls based client certificate/key supported mimik
  specific service discovery functions used by mimik_edge_services.c
  This is more of a use to mimik_edge_services and not for end application users.

mimik-rtos-sdk/test: contains usable single example test case
 - mimik-rtos-sdk/test/mimik_edge_services_test_client:
   ca_cert.pem     : sample and default SSL ca certificate pem file name
   client_cert.pem : sample and default SSL client certificate pem file name 
   client_key.pem  : sample and default SSL client key pem file name  

    Though all the 3 SSL certificates/key files are mandatory, developer can
    choose any file name and provide them as a buffer in their application.

   mimik_edge_services_test.c : Main example and readily usable test program making
                                use of mimik_edge_services api functions.

---------------------------------------------------------------------------------
main micro service discovery functions and structure details: 
---------------------------------------------------------------------------------

// mimik supernode discovery and subsequent available edge microservices discovery from supernode

typedef struct mk_edge_service_record {

  unsigned char sn_Name[S_MAX_SZ + 1]; //edge Supernode Name as null terminated string.
  unsigned char sn_Txt[S_MAX_SZ + 1];  //edge Supernode query response TEXT Record as null terminated string.
  char snIpStr[17];   //edge Supernode  ipv4 address as dotted string.
  unsigned short snPort;  //edge Supernode http port

  char *ser_rsp_buff;   // buffer to fill the response
  int  ser_rsp_max_buff_sz;  // max size of the buffer
  int  ser_rsp_rx_bytes;  // actual received bytes

}mk_edge_service_record;

typedef struct mk_edge_service_config {

  //node_type_id: [mandatory parameter] containing less than 255 characters.
  //It is of form "_mk-v12-4996e4c2442cc796f2c0ddb4e5e1627d._tcp.local" and is
  //needed to be recognized as a valid node in edge supernode discovery.
  char *node_type_id;

  //if_ipv4: [optional] host ipv4 address to use for communication else any
  //available network interface is used.
  char *if_ipv4;

  //max_timeoutsec: [optional] The maximum time in seconds the calling process
  //is willing to wait to get the result of edge service discovery.
  //If not given, various internal timeouts defaulted by multiple underlying
  //subsystems will be used, and the whole process could take as quick as few
  //few seconds upto several seconds.
  
  int max_timeoutsec;

  #define PEM_SER_KEY_SRC_PATH         0
  #define PEM_SER_KEY_SRC_BUF          1
  #define PEM_SER_KEY_SRC_EMBED_FILES  2
  char pem_key_data_source;

  // There are three options to provide client certificate, authority, and  key data
  //    option-1: as a readable file name with path
  // or option-2: store the keys in the mentioned default files for automatic loading
  // or option-3: as pointer to a buffer containing the data

  // The following default files for PEM_SER_KEY_SRC_BUF:  ca_cert.pem,
  // client_key.pem and client_cert.pem are embedded as binary data when
  // compiling the application only for ESP32 RTOS platform.  Hence if
  // PEM_SER_KEY_SRC_BUF is specified then the valid ssl certificate files
  // under the names "ca_cert.pem" , "client_key.pem" and  "client_cert.pem"
  // should be available at the time of compiling the application.

  char *ca_cert_pem_path;  // certificate Authority pem data as a file
  unsigned char *ca_cert_pem_buf; // Certificate Authority pem data in a buffer
  int ca_cert_pem_bytes;  // length of Certificate Authority pem data

  char *client_key_pem_path;  // Client Certificate pem data as a file
  unsigned char *client_key_pem_buf; // Client Certificate pem data in a buffer
  int client_key_pem_bytes;  // size of Client Certificate pem data

  char *client_cert_pem_path;  // Client Certificate pem data as a file
  unsigned char *client_cert_pem_buf; // Client Certificate pem data in a buffer
  int client_cert_pem_bytes;  // size of Client Certificate pem data

}mk_edge_service_config;

/**
 * @brief mimik_edge_service_discovery() function carries out multi-stage
 * supernode discovery process in a linklocal network, that the calling node
 * has taken a common network residence with. It then obtains information about
 * available services from the discovered edge Supernode securely using https.
 *      
 * This function will prepare a very minimal mimik specific mdns query used to
 * identify mimik edge super node in a link local network.  It also receives
 * the response answer sent from edge super node.
 *
 * @param[in]   mk_ser_cfg pointer to a filled mk_edge_service_config as
 *              briefed. [mandatory]

 * @param[out]  mk_ser_rec pointer to mk_edge_service_record where service
 *              records obtained from discovered edge

 * link local Suopernode is provided.
 *
 * @return      returns 0 on success and -1 on error
 */

int mimik_edge_service_discovery (mk_edge_service_config *mk_ser_cfg, mk_edge_service_record * mk_ser_rec);


typedef struct mk_edge_service_config {

  //node_type_id: [mandatory parameter] containing less than 255 characters.
  //It is of form "_mk-v12-4996e4c2442cc796f2c0ddb4e5e1627d._tcp.local" and is
  //needed to be recognized as a valid node in edge supernode discovery.
  char *node_type_id;

  //if_ipv4: [optional] host ipv4 address to use for communication else any
  //available network interface is used.
  char *if_ipv4;

  //max_timeoutsec: [optional] The maximum time in seconds the calling process
  //is willing to wait to get the result of edge service discovery.
  //If not given, various internal timeouts defaulted by multiple underlying
  //subsystems will be used, and the whole process could take as quick as few
  //few seconds upto several seconds.
  
  int max_timeoutsec;

  #define PEM_SER_KEY_SRC_PATH         0
  #define PEM_SER_KEY_SRC_BUF          1
  #define PEM_SER_KEY_SRC_EMBED_FILES  2
  char pem_key_data_source;

  // There are three options to provide client certificate, authority, and  key data
  //    option-1: as a readable file name with path
  // or option-2: store the keys in the mentioned default files for automatic loading
  // or option-3: as pointer to a buffer containing the data

  // The following default files for PEM_SER_KEY_SRC_BUF:  ca_cert.pem,
  // client_key.pem and client_cert.pem are embedded as binary data when
  // compiling the application only for ESP32 RTOS platform.  Hence if
  // PEM_SER_KEY_SRC_BUF is specified then the valid ssl certificate files
  // under the names "ca_cert.pem" , "client_key.pem" and  "client_cert.pem"
  // should be available at the time of compiling the application.

  char *ca_cert_pem_path;  // certificate Authority pem data as a file
  unsigned char *ca_cert_pem_buf; // Certificate Authority pem data in a buffer
  int ca_cert_pem_bytes;  // length of Certificate Authority pem data

  char *client_key_pem_path;  // Client Certificate pem data as a file
  unsigned char *client_key_pem_buf; // Client Certificate pem data in a buffer
  int client_key_pem_bytes;  // size of Client Certificate pem data

  char *client_cert_pem_path;  // Client Certificate pem data as a file
  unsigned char *client_cert_pem_buf; // Client Certificate pem data in a buffer
  int client_cert_pem_bytes;  // size of Client Certificate pem data

}mk_edge_service_config;

/**
 * @brief mimik_edge_service_discovery() function carries out multi-stage
 * supernode discovery process in a linklocal network, that the calling node
 * has taken a common network residence with. It then obtains information about
 * available services from the discovered edge Supernode securely using https.
 *      
 * This function will prepare a very minimal mimik specific mdns query used to
 * identify mimik edge super node in a link local network.  It also receives
 * the response answer sent from edge super node.
 *
 * @param[in]   mk_ser_cfg pointer to a filled mk_edge_service_config as
 *              briefed. [mandatory]

 * @param[out]  mk_ser_rec pointer to mk_edge_service_record where service
 *              records obtained from discovered edge

 * link local Suopernode is provided.
 *
 * @return      returns 0 on success and -1 on error
 */

int mimik_edge_service_discovery (mk_edge_service_config *mk_ser_cfg, mk_edge_service_record * mk_ser_rec);

Basically does the following making of other mimik client stub functions 
available as part of this library
   //Step1-mdns-udp: Discovers mimik edge Supernode by calling mimik_mdns_discover_supernode_client();
   //Step2-https-tcp: TSL/https GET service details from discovered mimik edge Supernode by calling mimik_tls_https_client_req_rsp();
   //Step3-copies the results obtained from mimik edge Supernode device.
 
