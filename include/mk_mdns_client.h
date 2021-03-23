/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File: mk_mdns_client.h 
 *  Author: Varadhan Venkataseshan
 */

#ifndef __MK_CLIENT_H__
#define __MK_CLIENT_H__

// mimik mdns thin super node discovery client library

#define MAX_NAME_SZ 255
#define SN_NAME_SZ 512
#define SN_TXT_SZ 512
typedef struct mk_mdns_sn_record {

  unsigned char sn_Name[SN_NAME_SZ + 1]; // taken from RRTYPE-PTR Pointer to Domain Name. Super Node Name as null terminated string.
  unsigned char sn_Txt[SN_TXT_SZ + 1];   // taken from  RRTYPE-TXT Record Concatenated as as single null terminated string.
  unsigned int snAddr;  // taken from additional RR, RRTYPE-A record super node ipv4 address
  char snIpStr[17];   // ipv4 address of super node stored as dotted string. This is same as snAddr
  unsigned short snPort;  // taken from additional RR, RRTYPE-SRV port field.

}mk_mdns_sn_record;

/**
 * @brief mimik_mdns_discover_supernode_client prepares and sends a mdns multicast query to solicit a response
 *      
 * This function will prepare a very minimal mimik specific mdns query
 * used to identify mimik edge super node in a link local network. 
 * It also receives the response answer sent from edge super node.
 *
 * @param[in]   qname     unique identification string used in the query txt. [mandatory]
 * @param[in]   ipv4      [optional] host ipv4 address to use for communication else any available n/w interface is used.
 * @param[out]  sn_result [optional] pointer to mk_mdns_sn_record where parsed super node response message will be stored.
 * @param[in]   msz       max size of buffer to sore the response: 512 bytes recommended.
 * @param[in]   timeoutsec   super node response receive timeoutsec in seconds.
 * @return                returns the length of received message on success and -1 on error
 */

int mimik_mdns_discover_supernode_client(char *qname, char *ipv4, struct mk_mdns_sn_record *sn_result, int timeoutsec);

#endif  //__MK_CLIENT_H__
