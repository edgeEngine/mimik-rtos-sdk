/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File: mimik_edge_services.h 
 *  Author: Varadhan Venkataseshan
 */

#ifndef __MIMIK_EDGE_SERVICES_H__
#define __MIMIK_EDGE_SERVICES_H__

// mimik supernode discovery and subsequent available microservices discovery
#include "mk_services_data.h"

#define S_MAX_SZ 512
typedef struct mk_edge_service_record {

  unsigned char sn_Name[S_MAX_SZ + 1]; //edge Supernode Name as null terminated string.
  unsigned char sn_Txt[S_MAX_SZ + 1];  //edge Supernode query response TEXT Record as null terminated string.
  char snIpStr[17];   //edge Supernode  ipv4 address as dotted string.
  unsigned short snPort;  //edge Supernode http port

  unsigned short ssl_service_port;  //service request ssl port

  char *ser_rsp_buff;   // buffer to fill the response
  int  ser_rsp_max_buff_sz;  // max size of the buffer
  int  ser_rsp_rx_bytes;  // actual received bytes

 //service_records srd contains c structure parsed output of received JSON service records.
 //It's data points to values contained in jroot opaque object.
  service_records srd;

 //jroot is an opaque object where parsed JSON object name/value data is dynamically allocated and stored.
 // call mimik_free_service_records() to free jroot memory.
  void *jroot;

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

  #define PEM_SER_KEY_SRC_PATH         1
  #define PEM_SER_KEY_SRC_BUF          2
  #define PEM_SER_KEY_SRC_EMBED_FILES  3
  char pem_ca_cert_data_source; //specific for ca_cert
  char pem_client_key_data_source; //specific for client_key
  char pem_client_cert_data_source; //specific for client_cert

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

/**
 * @brief mimik_free_service_records() function frees memory allocated to parse
 * received json object into service_records c structure members. It basically
 * frees the dynamically allocated memory used for jroot member. And also
 * resets the members of service_records srd from being used, as its strings
 * point to jroot opaque object.
 *
 * @param[in]   pointer to mk_edge_service_record * mk_ser_rec used in
 * mimik_edge_service_discovery()
 *
 * @return      returns 0 on success and -1 on error
 */
int mimik_free_service_records(mk_edge_service_record * mk_ser_rec);

/**
 * @brief mimik_print_service_records() function prints received edge nodes
 * service records stored in struct service_records -- c structure members.
 *
 * @param[in]   pointer to mk_edge_service_record * mk_ser_rec used in
 * mimik_edge_service_discovery()
 *
 */
void mimik_print_service_records(mk_edge_service_record * mk_ser_rec);

#endif  //__MIMIK_EDGE_SERVICES_H__
