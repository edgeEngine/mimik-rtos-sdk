/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File: mk_mdns_client.c
 *  Author: Varadhan Venkataseshan
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "mk_mdns_client.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_EMERG   0 
#define LOG_ALERT   1
#define LOG_CRIT    2
#define LOG_ERR     3
#define LOG_WARNING 4
#define LOG_NOTICE  5
#define LOG_INFO    6
#define LOG_DEBUG   7 

#define MK_LOG(lvl, fmt, args...) \
          ({ \
            if((g_log_lvl>=lvl)) { \
                printf(fmt,##args); \
                fflush(stdout); }\
          })


//global and static variables
static char g_log_lvl = LOG_INFO;

#define MDNS_HDRSZ 12
#define MK_MDNS_MULTICAST_ADDR "224.0.0.251"
#define MK_MDNS_MULTICAST_PORT 5353 

// mdns RRTYPE values for Resource Records: rfc1035
#define RRTYPE_A   1
#define RRTYPE_PTR 12
#define RRTYPE_TXT 16
#define RRTYPE_SRV 33


//static function declarations -- to be used internally.
static void mk_close_mcast_enpoint(int sd);
static int mk_create_mcast_enpoint(char *ipv4);
static int mk_prepare_qu_msg(unsigned char *buf, char *qname);
static int mk_send_mcast(int sd, unsigned char *txbuf, int txlen);
static int mk_recv_response(int sd, unsigned char *txbuf, int txlen, int timeoutsec);
static int mk_get_dotted_str_to_dns_name(char* src, unsigned char* dest);
static int mk_parse_response_mdns_pkt(unsigned char *rxpkt, int rxlen, struct mk_mdns_sn_record *sn_result);
static int mk_copy_rrname_back_reference(unsigned char *rxpkt, int rxlen, int ReadLen, unsigned char *dstBuf, int *pwlen, unsigned char *pU8Tmp);
static int mk_parse_get_rrname(unsigned char *rxpkt, int rxlen, int ReadLen, unsigned char *dstBuf, int skip_rrname);
static int mk_parse_get_rrtxt(unsigned char *rxpkt, int rxlen, int ReadLen, int RDLength, unsigned char *txtBuf);

//static function definitions.

/*
  mk_create_mcast_enpoint() creates a mdns multicast udp socket enpoint for 
  communication and returns the socket descriptor on success and -1 on failure
*/
static int mk_create_mcast_enpoint(char *ipv4)
{
    int sd = -1;
    int rc = -1;
    int ttl = 32;
    struct sockaddr_in addr = {0};
    struct ip_mreq ipm = {0};

    if ((!ipv4) || (strlen(ipv4) == 0)) {
       // MK_LOG(LOG_ERR, "%s() ipv4 is empty \n", __func__);
       addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else {
      addr.sin_addr.s_addr = inet_addr(ipv4);
    }
    ipm.imr_interface.s_addr = addr.sin_addr.s_addr;

    /*
     * create an endpoint for communication 
     */
    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sd < 0) {
       MK_LOG(LOG_ERR, "%s() socket() failed. err=%d(%s) \n", __func__,errno,strerror(errno));
       return -1;
    }

    /*
     * bind a name to the socket
     */
    addr.sin_family = AF_INET;
    rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0) {
       MK_LOG(LOG_ERR, "%s() bind() failed. err=%d(%s) \n", __func__,errno,strerror(errno));
       close(sd);
       return -1;
    }

// The following are needed only if we need to be a multicast listener

    /* 
     * Set the local device for a multicast socket -- using IP_MULTICAST_IF socket option
     */
     rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &addr.sin_addr, sizeof(struct in_addr));
     if (rc < 0) {
        MK_LOG(LOG_ERR, "%s() set IP_MULTICAST_IF failed. err=%d(%s) \n", __func__,errno,strerror(errno));
        close(sd);
        return -1;
     }

    /* 
     * Join to a multicast group -- using IP_ADD_MEMBERSHIP socket option
     */
     ipm.imr_multiaddr.s_addr = inet_addr(MK_MDNS_MULTICAST_ADDR);
     rc = setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &ipm, sizeof(struct ip_mreq));
     if (rc < 0) {
        MK_LOG(LOG_ERR, "%s() set IP_ADD_MEMBERSHIP failed. err=%d(%s) \n", __func__,errno,strerror(errno));
        close(sd);
        return -1;
     }

    /*
     *  Set  the time-to-live value of outgoing multicast packets for this socket
     *  TTL of 1 are restricted to the same subnet
     *  TTL of 32 are restricted to the same site
     */
     rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl,sizeof(ttl));
     if (rc < 0) {
        MK_LOG(LOG_ERR, "%s() set IP_MULTICAST_TTL failed. err=%d(%s) \n", __func__,errno,strerror(errno));
        close(sd);
        return -1;
     }

     MK_LOG(LOG_INFO, "%s() multicast socket=%d setup success \n", __func__,sd);

     return sd;
}


//returns the number of bytes written into dest including terminating 0
int mk_get_dotted_str_to_dns_name(char* src, unsigned char* dest)
{
  int count=0;
  int n=0;
  int dnsL=0;

  if ((!src) || (!dest)) {
     return -1;
  }

  while (n < MAX_NAME_SZ) {
    if(src[n] == '.'){
      dest[n-count] = count;
      count=0;
      n++;
    }
    else if(src[n] == 0){
      dest[n-count] = count;
      dest[n+1] = src[n];
      dnsL = n+2; //1+1 for prefix and terminating 0
      break;
    }
    else {
      dest[n+1] = src[n];
      n++;
      count++;
    }
  }

  return dnsL; 
}

/*
  mk_create_mcast_enpoint(int sd) closes passed socket descriptor.
*/
static void mk_close_mcast_enpoint(int sd)
{
   if (sd > 0){
     close(sd);
   }
}

/* mdns header

 0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               id              |           flags               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               queries         |           answers             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               auth_rr         |           add_rr              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
[.......c_str 0 terminated variable Length query txt ...........]
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               type            |           class/QU            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

our mdns query signature: id=0,flags=0,queries=1,answers=0,auth_rr=0,add_rr=0,type=12(ptr),QU

*/


/**
 * @brief mk_prepare_qu_msg prepares a simple minimal mimik specific mdns query 
 *      
 * This function will prepare a very minimal mimik specific mdns query
 * used to identify mimik edge super node in a local network.
 *
 * @param[in]   buf       pointer to a msg buffer to store a prepared mdns query message.
 * @param[out]  buf       pointer to a msg buffer where prepared mdns query message will be stored.
 * @return                returns the length of prepared message filled into buffer.
 */
static int mk_prepare_qu_msg(unsigned char *buf, char *qname)
{
   uint16_t *pU16 = NULL;
   int qnlen = 0;
   int txlen = 0;
   uint16_t val16 = 0;

   if ((!buf)||(!qname)) {
      MK_LOG(LOG_ERR,"%s() NULL parameters \n",__func__);
      return 0;
   }

   // Fill header
   memset(buf,0,MDNS_HDRSZ);
   pU16 = (uint16_t *)&buf[0];
   // pU16[0] = 0; //id
   // pU16[1] = 0; //flags
   pU16[2] = htons(1); //num queries 
   // pU16[3] = 0; //answer
   // pU16[4] = 0; //auth_rr
   // pU16[4] = 0; // add_rr
   txlen = MDNS_HDRSZ;

   // Fill formatted question txt: "a.bcde.xyz" to "1a4bcde3xyz"
   qnlen = mk_get_dotted_str_to_dns_name(qname,&buf[txlen]);
   if ( qnlen <= 0 ) {
      MK_LOG(LOG_ERR,"%s() mk_get_dotted_str_to_dns_name error \n",__func__);
      return -1;
   }

  txlen += qnlen;

  //Fill type
  pU16 = (uint16_t *)&buf[txlen];
  val16 = RRTYPE_PTR;
  pU16[0] = htons(val16);
  txlen += 2;

  //Fill class/QU
  val16 = 1; // 1 for class internet
  val16 |= (1 << 15); // for unicast
  pU16 = (uint16_t *)&buf[txlen];
  pU16[0] = htons(val16);
  txlen += 2;

  return txlen;
}

int mk_recv_response(int sd, unsigned char *rxbuf, int rxlen, int timeoutsec)
{
  int rc = 0;
  struct sockaddr_in fromaddr = {0};
  socklen_t addrlen = sizeof(fromaddr);

  if (timeoutsec > 0) {
     struct timeval tout = {0};
     tout.tv_sec = timeoutsec;
     rc = setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tout, sizeof(tout));
  }

  memset(rxbuf, 0, rxlen);
  rc = recvfrom(sd, rxbuf, rxlen, 0,(struct sockaddr *)&fromaddr, &addrlen);
  if ( rc <= 0) {
     MK_LOG(LOG_ERR, "%s() recvfrom() failed. err=%d(%s) \n", __func__,errno,strerror(errno));
     return -1;
  }

  // MK_LOG(LOG_INFO," !!! Successful response from edge SuperNode(ip=%s) rxlen=%d !!!\n ",inet_ntoa(fromaddr.sin_addr), rc);

  return rc;
}

int mk_send_mcast(int sd, unsigned char *txbuf, int txlen)
{
  struct sockaddr_in toaddr = {0};
  int rc = 0;

  if ((sd <= 0)||(!txbuf)||(txlen <= 0)) {
     return -1;
  }

  toaddr.sin_family = AF_INET;
  toaddr.sin_port = htons(MK_MDNS_MULTICAST_PORT);
  toaddr.sin_addr.s_addr = inet_addr(MK_MDNS_MULTICAST_ADDR);

  rc = sendto(sd, txbuf, txlen, 0, (struct sockaddr *)&toaddr,sizeof(toaddr));
  if (rc < 0) {
     MK_LOG(LOG_ERR, "%s() sendto() failed. err=%d(%s) \n", __func__,errno,strerror(errno));
  }

  return rc;
}

//global library function definitions.
#define DFT_RX_TIMEOUT_SEC 5
int mimik_mdns_discover_supernode_client(char *qname, char *ipv4, struct mk_mdns_sn_record *sn_result, int timeoutsec)
{
   int sd = -1;
   int rc = -1;
   int txlen = 0;
   int rxlen = 0;
   #define MAX_MDNS_BUF 1024
   unsigned char mbuf[MAX_MDNS_BUF+1] = {0};

   if (timeoutsec <= 0) {
      timeoutsec = DFT_RX_TIMEOUT_SEC;
   }

   sd = mk_create_mcast_enpoint(ipv4);
   if (sd <= 0) {
      MK_LOG(LOG_ERR,"%s() mk_create_mcast_enpoint failed\n",__func__);
      return -1;
   }

   if ((!qname) || (strlen(qname) > MAX_NAME_SZ) || (!sn_result)) {
      MK_LOG(LOG_ERR,"%s() Error: Invalid NULL pararameters \n",__func__);
      return -1;
   }

   txlen = mk_prepare_qu_msg(mbuf, qname);
   if (txlen <= 0) {
      MK_LOG(LOG_ERR,"%s() mk_prepare_qu_msg failed \n",__func__);
      mk_close_mcast_enpoint(sd);
      return -1;
   }

   rc = mk_send_mcast(sd, mbuf, txlen);
   if (rc <= 0) {
      MK_LOG(LOG_ERR,"%s() mk_send_mcast failed \n",__func__);
      mk_close_mcast_enpoint(sd);
      return -1;
   }

   MK_LOG(LOG_NOTICE," !!! %s() successfully sent sd=%d txlen=%d rc=%d !!! \n",__func__,sd,txlen,rc);

   rxlen = mk_recv_response(sd, mbuf, MAX_MDNS_BUF, timeoutsec);
   if (rxlen <= 0) {
      MK_LOG(LOG_ERR,"%s() mk_recv_response failed \n",__func__);
      mk_close_mcast_enpoint(sd);
      return -1;
   }

   if (rxlen > 0) {
      MK_LOG(LOG_NOTICE," !!! %s() successfully received response sd=%d rxlen=%d !!! \n",__func__,sd,rxlen);
      memset(sn_result,0,sizeof(struct mk_mdns_sn_record));
      // save parsed response message in sn_result if given
      rc = mk_parse_response_mdns_pkt(mbuf, rxlen, sn_result);
      if (rc < 0) {
        MK_LOG(LOG_ERR," %s() mk_parse_response_mdns_pkt error rc=%d rxlen=%d \n",__func__,rc,rxlen);
      }
      else {
         MK_LOG(LOG_NOTICE,"\n %s() SUPERNODE DISCOVERY Success: \n sn Address: %s \n sn Port: %hu \n sn Name: %s \n sn Text: %s \n\n",
                   __func__,sn_result->snIpStr,sn_result->snPort,sn_result->sn_Name,sn_result->sn_Txt);
      }
     
      //TODO may be check the if the response RR PTR resource record name contains
      // our query as a substring to confirm it is our valid response, instead of check for _mk prefix
   }

   
   mk_close_mcast_enpoint(sd);
   return rxlen;
}

/*mDNS:  https://tools.ietf.org/html/rfc6762 */
/*DNS implementation:  https://tools.ietf.org/html/rfc1035 */
// based on DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION rfc1035

/*
// Resource Records

 0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
[.......c_str 0 terminated variable Length --- RRNAME...........]   <---n1s1n2ns2...0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            RRTYPE             |  CACHE-FLUSH(1) + RRCLASS(15) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 TTL(Time interval in seconds)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           RDLENGTH            |  <----- length of the RDATA in bytes
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
[................... variable RDATA resource data ..............]  <--- varies by RRTYPE

RRTYPE( 16 bits ) : record types
RRtype - value - resulting RDATA size and type
//From Answer Record
PTR    -  12   -  Pointer to Domain Name (contains our Super Node Name)
//From Additional Records
A      -  1    -  Address record (32-bit IPv4 address in network order)
TXT    -  16   -  Text Record  (All our supernode json strings are sent here)
SRV    -  33   -  Service locator (contains our service TCP port)
*/

//returns 0 on success and -1 on failure
static int mk_parse_response_mdns_pkt(unsigned char *rxpkt, int rxlen, struct mk_mdns_sn_record *sn_result)
{

/*
   // Our Super Node response typically contains:
   // dns.flags.response == 1  // It is a response
   // dns.count.queries == 0   //  0 question
   // dns.count.answers == 1   //  Answer RRs: 1
       // PTR(12)  -  Pointer to Domain Name (contains our Super Node Name)
   // dns.count.auth_rr == 0   //  Authority RRs: 0
   // dns.count.add_rr == 4    //  Additional RRs: 4
       // A(1)    -  Address record (32-bit IPv4 address in network order)
       // TXT(16) -  Text Record (All our supernode json strings are sent here as L1S1L2S2L3S3...)
       // SRV(33) -  Service locator (contains our service TCP port)
*/

   uint16_t *pU16 = (uint16_t *)rxpkt;
   int readlen = 0;
   int rc = 0;

   uint16_t val16 = 0;
   uint16_t ans_rr_cnt = 0;
   uint16_t aut_rr_cnt = 0;
   uint16_t add_rr_cnt = 0;
   uint16_t t_rr_cnt = 0;
   uint16_t r = 0;

   if ((!rxpkt)||(rxlen < MDNS_HDRSZ)) {
      MK_LOG(LOG_ERR,"%s() error rxlen = %d \n",__func__,rxlen);
      return -1;
   }

   // mdns Identifier(id)  // Not interested in mdns id value skip
   // val16 = ntohs(pU16[0]);

   // check flags for QR (Query(0)/Response(1)) Bit at (0x8000)
   val16 = ntohs(pU16[1]);
   if ((val16 & (1<<15)) != 0x8000) {
     MK_LOG(LOG_ERR,"%s() mdns.flags.response not as expected. flags=%hu\n",__func__,val16);
     return -1;
   }

   // check for dns.count.queries == 0
   val16 = ntohs(pU16[2]);
   if (val16 != 0) {
     MK_LOG(LOG_ERR,"%s() mdns.count.queries(%hu) != expected(0) \n",__func__,val16);
     return -1;
   }

   // dns.count.answers == 1  // response should have RR:1 for answers 
   ans_rr_cnt = ntohs(pU16[3]);

   // check for dns.count.auth_rr == 0 // should have RR: 0 for 
   aut_rr_cnt = ntohs(pU16[4]);
   if (aut_rr_cnt != 0) {
     MK_LOG(LOG_INFO,"%s() mdns.count.auth_rr(%hu) != expected(0) \n",__func__,val16);
   }

   // dns.count.add_rr > 1    // should have Additional RRs: 4
   add_rr_cnt = ntohs(pU16[5]);

   t_rr_cnt = ans_rr_cnt + aut_rr_cnt + add_rr_cnt;

   if (t_rr_cnt == 0) {
     MK_LOG(LOG_ERR,"%s() unexpected response records =%u \n",__func__,t_rr_cnt);
     return -1;
   }
   
   readlen += MDNS_HDRSZ;
  
  // MK_LOG(LOG_DEBUG,"%s() t_rr_cnt = %d \n",__func__,t_rr_cnt);

   for (r=0; (r < t_rr_cnt) && (readlen < rxlen); r++) {

      uint16_t RRType = 0;
      uint16_t RDLength = 0;

     // MK_LOG(LOG_DEBUG,"\n\n %s rr-loop(r=%d) readlen=%d \n",__func__,r,readlen);

      // We are not interested in copying RRNAME now: just parse and skip read bytes
      // However when we need a name and directed here through a
      // a refernce, then that time will parse that section.
      // The intent is to MINIMIZE parsing and copying as much as possible, only to what we NEED.

      rc = mk_parse_get_rrname(rxpkt, rxlen, readlen, NULL, 1);
      if ( rc > 0 ) {
         readlen += rc;
      }

      if (readlen >= rxlen) {
         MK_LOG(LOG_ERR,"%s() readlen(%d) > rxlen(%d) r=%d error \n",__func__,readlen,rxlen,r);
	 return -1;
      }

      // RRTYPE - 2 bytes in network byte order
      pU16 = (uint16_t *)&rxpkt[readlen];
      RRType = ntohs(pU16[0]);
      readlen += 2;

      // CACHE-FLUSH(1) + RRCLASS(15) - skip, we are not interested RRCLASS
      readlen += 2;

      //TTL - skip,  We are not interested in TTL - 4 bytes 
      readlen += 4;

      // RDLENGTH - 2 bytes in network byte order
      pU16 = (uint16_t *)&rxpkt[readlen];
      RDLength = ntohs(pU16[0]);
      readlen += 2;

     // MK_LOG(LOG_DEBUG,"%s() r=%d RDLength=%d readlen=%d RRType=%d \n",__func__,r,RDLength,readlen,RRType);

      // Now process variable RDATA resource data based on RRType
      switch (RRType) {

	 case RRTYPE_PTR:
	  // MK_LOG(LOG_DEBUG,"%s(RRTYPE_PTR) r=%d RDLength=%d readlen=%d RRType=%d \n",__func__,r,RDLength,readlen,RRType);
	    //get PTRDNAME name containing backward reference to names if any.
	    //L1.S1.L2.S2.....c0-pointer[2bytes]0
	    // https://tools.ietf.org/html/rfc1035 : 3.3.12. PTR RDATA format
	    // and section 4.1.4. Message compression
            mk_parse_get_rrname(rxpkt, rxlen, readlen, sn_result->sn_Name, 0);
	    MK_LOG(LOG_INFO,"%s(RRTYPE_PTR) Parsed SuperNode Record Name=%s \n",__func__,sn_result->sn_Name);
	 break;

	 case RRTYPE_SRV: 
	   // MK_LOG(LOG_DEBUG,"%s(RRTYPE_SRV) r=%d RDLength=%d readlen=%d RRType=%d \n",__func__,r,RDLength,readlen,RRType);
	    pU16 = (uint16_t *)&rxpkt[readlen];
	    //[priority(2 bytes)+weight(2 bytes)+port(2 bytes )+hostname...(variabe length)]
	    // skip reading priority, weight, and hostname as we do not need.
	    sn_result->snPort = ntohs(pU16[2]);
	    MK_LOG(LOG_INFO,"%s(RRTYPE_SRV) Parsed SuperNode port=%hu \n",__func__,sn_result->snPort);
	 break;

	 case RRTYPE_A:
	   // MK_LOG(LOG_DEBUG,"%s(RRTYPE_A) r=%d RDLength=%d readlen=%d RRType=%d \n",__func__,r,RDLength,readlen,RRType);
	    //contains 4 bytes ipv4 address in network byte order
	    //struct in_addr in = {0};
	    sn_result->snAddr = *((unsigned int*)&rxpkt[readlen]);
	    //in.s_addr = sn_result->snAddr;
	    snprintf(sn_result->snIpStr,sizeof(sn_result->snIpStr),"%u.%u.%u.%u",
			  rxpkt[readlen], rxpkt[readlen+1], rxpkt[readlen+2], rxpkt[readlen+3]);
	    //strncpy(sn_result->snIpStr,inet_ntoa(in),sizeof(sn_result->snIpStr));
	    MK_LOG(LOG_INFO,"%s(RRTYPE_A) Parsed SuperNode ipv4=%s and as in.s_addr=%u \n",__func__,sn_result->snIpStr,sn_result->snAddr);
	 break;

	 case RRTYPE_TXT:
	   // MK_LOG(LOG_DEBUG,"%s(RRTYPE_TXT) r=%d RDLength=%d readlen=%d RRType=%d \n",__func__,r,RDLength,readlen,RRType);
            mk_parse_get_rrtxt(rxpkt, rxlen, readlen, RDLength, sn_result->sn_Txt);
	    MK_LOG(LOG_INFO,"%s(RRTYPE_TXT) Parsed SuperNode Record Txt=%s \n",__func__,sn_result->sn_Txt);
	 break;

	 default:
	    //break and proceed.
	    // MK_LOG(LOG_DEBUG,"%s(default) r=%d RDLength=%d readlen=%d RRType=%d SKIPPING \n",__func__,r,RDLength,readlen,RRType);
	 break;

       } //end of switch RRType/RRDATA parsing

      //update index with RDLength
      readlen += RDLength;

   } // end of for RR records processing

   // MK_LOG(LOG_INFO,"%s(leave) r=%d readlen=%d \n",__func__,r,readlen);

   return 0;
}

int mk_parse_get_rrtxt(unsigned char *rxpkt, int rxlen, int ReadLen, int RDLength, unsigned char *txtBuf)
{
   int sslen = 0;
   int rlen = 0;
   int wlen = 0;
   int readlen = ReadLen;

   if ((!rxpkt)||(!txtBuf)) {
      return -1;
   }
   while ((readlen < rxlen) && (rlen < RDLength)) {
    // get substring length
    sslen = rxpkt[readlen];
    rlen++;
    readlen++;
           
    if (sslen == 0) {
        break;
    }
    else if (sslen < RDLength) {
       memcpy(&txtBuf[wlen],&rxpkt[readlen],sslen);
       wlen += sslen;
       rlen += sslen;
       readlen += sslen;
    }
    else if (sslen >= RDLength) {
       return -1;
    }
  } //end of while
  txtBuf[wlen] = 0;

  printf("mk_parse_get_rrtxt, wlen: %d, text end:%c, text end after: %x, last:%c\n", wlen, txtBuf[204], txtBuf[205], txtBuf[wlen-1]);  //LMJ test
  return 0;
}

int mk_copy_rrname_back_reference(unsigned char *rxpkt, int rxlen, int ReadLen, unsigned char *dstBuf, int *pwlen, unsigned char *pU8Tmp)
{
     if ((rxpkt && dstBuf && pwlen && pU8Tmp)) {
           int wlen = *pwlen; 
           // copy back reference RRName string if requested.
           int ridx = pU8Tmp[1];
           if ( wlen > 0 ) {
             dstBuf[wlen] = '.';
             wlen++;
           }
           while ((ridx > 0) && (ridx < ReadLen) && (rxpkt[ridx] != 0)) {
               int refL = rxpkt[ridx];
               ridx++;
               memcpy(&dstBuf[wlen], &rxpkt[ridx], refL);
               wlen += refL;
               ridx += refL;
               if (rxpkt[ridx] == 0) {
                 dstBuf[wlen] = 0;
                 wlen++;
                 break;
               }
               else {
                   dstBuf[wlen] = '.';
                   wlen++;
                   if (rxpkt[ridx] == 0xC0) {
                     ridx = rxpkt[ridx+1];
                   }
               }
           } //while copying pointer backward reference string
           if (wlen > (*pwlen)) {
              *pwlen = wlen;
           }
     }
     return 0;
}

//parses RRNAME and advances the pointer
//if skip_rrname is true, it simply skips parsing and copying strings, but advances readlen
// returns -1 on error and returns total bytes advanced by this function
int mk_parse_get_rrname(unsigned char *rxpkt, int rxlen, int ReadLen, unsigned char *dstBuf, int skip_rrname)
{
      int readlen = 0;
      int rbytes = 0;
      int wlen = 0;
      unsigned char *pU8Tmp = NULL;

      if(!rxpkt) {
        return -1;
      }

      readlen = ReadLen;
      pU8Tmp = &rxpkt[readlen];

      // 4 ways a RRNAME string can be presented
      //1) RRNAME [label:1byte:pointer(0XC0))][stringaddress-1byte]
      //2) RRNAME [lablel:1byte:strlen][string .....][0]
      //3) RRNAME [lablel:1byte:strlen][string .....][label:1byte:pointer(0XC0)][stringaddress-1byte]
      //4) RRNAME [lablel:1byte:0][Root label]
      if (pU8Tmp[0] == 0XC0) {
         //1) RRNAME [label:1byte:pointer(0XC0))][stringaddress-1byte]
         //skip label 1 byte and pointer 1 byte
        // MK_LOG(LOG_DEBUG,"%s(category1) label+pointer :  2 bytes \n",__func__);

         if ((skip_rrname == 0) && (dstBuf)) {
             mk_copy_rrname_back_reference(rxpkt, rxlen, ReadLen, dstBuf, &wlen, pU8Tmp);
         }

         readlen += 2;
      }
      else if (pU8Tmp[0] == 0) {
         //4) RRNAME [lablel:1byte:0][Root label]
	 readlen += 1;
	// MK_LOG(LOG_DEBUG,"%s(category-4) label 0 root label: 1 byte \n",__func__);
      }
      else {
        while (readlen < rxlen) {

           if ((skip_rrname == 0) && (dstBuf)) {
              memcpy(&dstBuf[wlen],&pU8Tmp[1],pU8Tmp[0]);
              wlen += pU8Tmp[0];
           }
	   readlen += pU8Tmp[0];
	   // skip label
	   readlen += 1;
	  // MK_LOG(LOG_DEBUG,"\n %s() label+string : (1 + %d) bytes \n",__func__,pU8Tmp[0]);

	   // update pU8Tmp again
	   pU8Tmp = &rxpkt[readlen];
	   // Now find again what the string is terminated with either 0 or with pointer 0XC0
	   if (pU8Tmp[0] == 0XC0) {

             if ((skip_rrname == 0) && (dstBuf)) {
               // copy back reference RRName string if requested.
                mk_copy_rrname_back_reference(rxpkt, rxlen, ReadLen, dstBuf, &wlen, pU8Tmp);
             }
	     //3) RRNAME [lablel:1byte:strlen][string .....][label:1byte:pointer(0XC0)][stringaddress-1byte]
	     //skip label 1 byte and pointer 1 byte
	     readlen += 2;
	    // MK_LOG(LOG_DEBUG,"%s(category-3) label+string and end marker label+pointer : 2 bytes \n",__func__);
	     break;
	   }
	   else if (pU8Tmp[0] == 0) {
	     //2) RRNAME [lablel:1byte:strlen][string .....][0]
             if ((skip_rrname == 0) && (dstBuf)) {
                dstBuf[wlen] = 0;
                wlen++;
             }
	     readlen += 1;
	    // MK_LOG(LOG_DEBUG,"%s(category-2) label+string and string terminator 0 : 1 byte \n",__func__);
	     break;
	   }
	   else {
             if ((skip_rrname == 0) && (dstBuf)) {
                dstBuf[wlen] = '.';
                wlen++;
             }
	    // MK_LOG(LOG_DEBUG,"%s(category-check) continuing with next substring ...\n",__func__);
	     continue;
	   }

        } // end while substring loop of RRNAME
      }

      if (readlen > (ReadLen)) {
         rbytes = readlen - ReadLen;
      }
      return rbytes;
}

