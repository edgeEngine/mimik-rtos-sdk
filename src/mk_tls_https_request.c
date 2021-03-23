/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File:   mk_tls_https_request.c
 *  Author: Varadhan Venkataseshan
 */

// mk_tls_https_request.h and mk_tls_https_request.c provides an https
// interface client stub. It utilizes mbedtls supplied TLS/SSL library and
// provides a facility to connect and transact securely via https with edge
// supernode using mimik supported REST API's and client certificates.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#if !defined(__linux__)
#include "mk_tls_https_request.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"

#ifndef MK_LOG
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

#endif


 // TLS/SSL parameters for mbedtls libray
typedef struct mk_mbedtls_conn_params {

    mbedtls_net_context net_sd; // server_fd;

    // entropy is the randomness collected
    mbedtls_entropy_context entropy_ctx;  // entropy;

    //Counter mode Deterministic Random Byte Generator
    mbedtls_ctr_drbg_context ctr_drbg_ctx; // ctr_drbg;

    //SSL/TLS configuration to be shared between mbedtls_ssl_context structures.
    mbedtls_ssl_config  ssl_conf;  // conf;
    mbedtls_ssl_context ssl_ctx;  // ssl;

    // CA_CERTIFICATE, CLIENT_CERTIFICATE, CLIENT_KEY
    mbedtls_x509_crt x509_cacert;  // cacert;
    mbedtls_x509_crt x509_clicert; // clicert;
    mbedtls_pk_context x509_pkey;  // pkey;

}mk_mbedtls_conn_params;

#define TX_HTTPS_BUF_512 512
#define TX_HTTPS_BUF_1024 1024 
#define TX_HTTPS_BUF_SZ TX_HTTPS_BUF_512
#define RX_HTTPS_BUF_10K 10240
#define RX_HTTPS_BUF_12K 12288
#define RX_HTTPS_BUF_15K 15360
#define RX_HTTPS_BUF_SZ RX_HTTPS_BUF_15K

#define SSL_READ_SUBTIMEOUT_MS 500
typedef struct mk_tls_https_info {
   mk_mbedtls_conn_params mtlsc;
   mk_https_req  mkrequest;
   unsigned char txbuf[TX_HTTPS_BUF_SZ];
   int txlen;
   unsigned char rxbuf[RX_HTTPS_BUF_SZ];
   int rxlen;
   int content_length;
   int timeoutms;
   int read_subtimeout_ms;
}mk_tls_https_info;

//static function declarations:
static int mk_load_pem_certifcates(mk_https_req *mkreq, mk_mbedtls_conn_params *pmtls);
static int mk_prepare_send_https_request(mk_tls_https_info *pmkctx);
static int mk_recv_https_response(mk_tls_https_info *pmkctx);
//returns 0 on success and -1 on error
static int mk_prepare_tls_ssl_ctx(mk_tls_https_info *pmkctx);
static int mk_tls_ssl_free(mk_tls_https_info *pmkctx);
char * mk_get_https_content_data(unsigned char *rx_msg, int rxBytes, int *pcontent_length);

static long int mk_get_elaspedms(struct timeval *ptstart);

//global and static variables
static char g_log_lvl = LOG_NOTICE;
static mk_tls_https_info mk_ctx;

// There are three options to provide client certificate, authority, and  key data
//    option-1: as a readable file name with path
// or option-2: store the keys in the mentioned default files for automatic loading
// or option-3: as pointer to a buffer containing the data

// The following default files are embedded as binary data in 
// and is available to the component and the file contents will be 
// contents will be added to the .rodata section in flash, and are available via symbol names
// https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html#embedding-binary-data

/*
# When building for esp32 devkit, need to setup component.mk as follows:
# embed files as binary data symbols
COMPONENT_EMBED_TXTFILES := ca_cert.pem                                       
COMPONENT_EMBED_TXTFILES += client_cert.pem                                   
COMPONENT_EMBED_TXTFILES += client_key.pem                                    
*/

extern const uint8_t ca_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t ca_cert_pem_end[]   asm("_binary_ca_cert_pem_end");

#ifdef ENABLE_BUILDTIME_EMBED_CLIENT_CERT_PEM_FILE
extern const uint8_t client_cert_pem_start[] asm("_binary_client_cert_pem_start");
extern const uint8_t client_cert_pem_end[]   asm("_binary_client_cert_pem_end");
#endif

#ifdef ENABLE_BUILDTIME_EMBED_CLIENT_KEY_PEM_FILE
extern const uint8_t client_key_pem_start[] asm("_binary_client_key_pem_start");
extern const uint8_t client_key_pem_end[]   asm("_binary_client_key_pem_end");
#endif

static int mk_load_pem_certifcates(mk_https_req *mkreq, mk_mbedtls_conn_params *pmtls)
{
    int ret = 0;
    int slen = 0;

    //-----------------------  BEGIN loadig ca_cert --------------------------
    MK_LOG(LOG_INFO,"%s() Loading ca_cert pem_ca_cert_data_source=%d \n",__func__,mkreq->pem_ca_cert_data_source);
    // assign SSL key and certificate data buffers based on source
    if (mkreq->pem_ca_cert_data_source == PEM_KEY_SRC_PATH) {
       // ---------------------- ca_certificate as file ----------------------
       if (!mkreq->ca_cert_pem_path) {
	   MK_LOG(LOG_ERR,"%s(Error) empty config file paths: ca_cert, client_cert, clinet_key pem file path\n",__func__);
	   return -1;
       }
       ret = mbedtls_x509_crt_parse_file(&pmtls->x509_cacert, mkreq->ca_cert_pem_path);
       if (ret < 0) {
	   MK_LOG(LOG_ERR,"%s(Error) mbedtls_x509_crt_parse err loading ca_cert.pem file=%s ret=-%x \n",
		      __func__,mkreq->ca_cert_pem_path,-ret);
	   return -1;
       }
       MK_LOG(LOG_INFO,"%s(Success) Loading ca_cert.pem certificate file=%s \n",__func__,mkreq->ca_cert_pem_path);
    } else {

       if (mkreq->pem_ca_cert_data_source == PEM_KEY_SRC_EMBED_FILES) {
	  // PEM_KEY_SRC_EMBED_FILES
          // Certificate Authority pem data
	  mkreq->ca_cert_pem_buf = (uint8_t *)ca_cert_pem_start;
          mkreq->ca_cert_pem_bytes = (ca_cert_pem_end-ca_cert_pem_start);

	  MK_LOG(LOG_DEBUG ,"%s(PEM_KEY_SRC_EMBED_FILES) ca_cert_pem_bytes=%d \n", __func__,mkreq->ca_cert_pem_bytes);
       }

       if (!mkreq->ca_cert_pem_buf) {
	   MK_LOG(LOG_ERR,"%s(Error) empty certificate pem data bufffers: ca_cert, client_cert, clinet_key \n",__func__);
	   return -1;
       }

       slen = (int)strlen((char *)mkreq->ca_cert_pem_buf);
       if (mkreq->ca_cert_pem_bytes == slen) {
          // need to include the length of terminating null bytes when mbedtls_x509_crt_parse for parsing
          // pem data in a buffer
          //NOTE: In the case of embedded file as buffer the terminating null character is included already.
          mkreq->ca_cert_pem_bytes += 1;
          MK_LOG(LOG_NOTICE , "%s() adding an extra byte for the terminating null byte to ca_cert_pem_bytes\n",__func__);
       }

       // ---------------------- ca_certificate in buffer --------------------
       ret = mbedtls_x509_crt_parse(&pmtls->x509_cacert, mkreq->ca_cert_pem_buf, mkreq->ca_cert_pem_bytes);
       if (ret < 0) {
	   MK_LOG(LOG_ERR,"%s(Error) mbedtls_x509_crt_parse err loading ca_cert.pem bytes=%d ret=-%x \n ",
		      __func__,mkreq->ca_cert_pem_bytes,-ret);
	   return -1;
       }
       MK_LOG(LOG_INFO,"%s(Success) Loading ca_cert.pem certificate...len=%d \n ",__func__,mkreq->ca_cert_pem_bytes);
    }
    //-----------------------  DONE loading ca_cert --------------------------

    //-----------------------  BEGIN loadig client_cert ----------------------
    MK_LOG(LOG_INFO,"%s() Loading client_cert, .... pem_client_cert_data_source=%d \n",__func__,mkreq->pem_client_cert_data_source);
    if (mkreq->pem_client_cert_data_source == PEM_KEY_SRC_PATH) {
       // ---------------------- client_certificate as file ------------------
       ret = mbedtls_x509_crt_parse_file(&pmtls->x509_clicert, mkreq->client_cert_pem_path);
       if (ret < 0) {
	   MK_LOG(LOG_ERR,"%s(Error) mbedtls_x509_crt_parse err loading client_cert.pem file=%s ret=-%x \n",
		      __func__,mkreq->client_cert_pem_path ,-ret);
	   return -1;
       }
       MK_LOG(LOG_INFO,"%s(Success) Loading client_cert.pem certificate file=%s \n ",__func__,mkreq->client_cert_pem_path);
    } else {
       if (mkreq->pem_client_cert_data_source == PEM_KEY_SRC_EMBED_FILES) {
	  // PEM_KEY_SRC_EMBED_FILES
          // Client Certificate pem data
#ifdef ENABLE_BUILDTIME_EMBED_CLIENT_CERT_PEM_FILE
	  mkreq->client_cert_pem_buf = (uint8_t *)client_cert_pem_start;
          mkreq->client_cert_pem_bytes = (client_cert_pem_end-client_cert_pem_start); 
	  MK_LOG(LOG_DEBUG ,"%s(PEM_KEY_SRC_EMBED_FILES) client_cert_pem_bytes=%d strlen(client_cert_pem_buf)=%d \n", 
                           __func__,mkreq->client_cert_pem_bytes,(int)strlen((char *)mkreq->client_cert_pem_buf));
#else
         MK_LOG(LOG_ALERT, "ALERT: %s() PEM_KEY_SRC_EMBED_FILES option for pem_client_cert_data_source is not supported ...\n",__func__);
         MK_LOG(LOG_ALERT, "ALERT: #define ENABLE_BUILDTIME_EMBED_CLIENT_CERT_PEM_FILE at build time to enable it. \n");
         return -1;
#endif
       }
       if (!mkreq->client_cert_pem_buf) {
	   MK_LOG(LOG_ERR,"%s(Error) empty certificate pem data bufffers: ca_cert, client_cert, clinet_key \n",__func__);
	   return -1;
       }
       slen = (int)strlen((char *)mkreq->client_cert_pem_buf);
       if (mkreq->client_cert_pem_bytes == slen) {
          // need to include the length of terminating null bytes when mbedtls_x509_crt_parse for parsing
          // pem data in a buffer
          //NOTE: In the case of embedded file as buffer the terminating null character is included already.
          mkreq->client_cert_pem_bytes += 1;
          MK_LOG(LOG_NOTICE , "%s() adding an extra byte for the terminating null byte to client_cert_pem_bytes\n",__func__);
       }
       // ----------------- client_certificate in buffer ---------------------
       ret = mbedtls_x509_crt_parse(&pmtls->x509_clicert, mkreq->client_cert_pem_buf, mkreq->client_cert_pem_bytes);
       if (ret < 0) {
	   MK_LOG(LOG_ERR,"%s(Error) mbedtls_x509_crt_parse err loading client_cert.pem bytes=%d ret=-%x \n ",
		      __func__,mkreq->client_cert_pem_bytes,-ret);
	   return -1;
       }
       MK_LOG(LOG_INFO,"%s(Success) Loading client_cert.pem certificate...len=%d \n ",__func__,mkreq->client_cert_pem_bytes);
    }
    //-----------------------  DONE loading client_cert ----------------------

    //-----------------------  BEGIN loadig client_key -----------------------
    MK_LOG(LOG_INFO,"%s() Loading client_key .... pem_client_key_data_source=%d \n",__func__,mkreq->pem_client_key_data_source);
    if (mkreq->pem_client_key_data_source == PEM_KEY_SRC_PATH) {

       if (!mkreq->client_key_pem_path) {
	   MK_LOG(LOG_ERR,"%s(Error) empty config file paths: ca_cert, client_cert, clinet_key pem file path\n",__func__);
	   return -1;
       }

       // ---------------------- client_key as file ----------------------
       ret = mbedtls_pk_parse_keyfile(&pmtls->x509_pkey, mkreq->client_key_pem_path,NULL);
       if (ret < 0) {
	   MK_LOG(LOG_ERR,"%s(Error) mbedtls_x509_crt_parse err loading client_key.pem file=%s ret=-%x \n ",
		      __func__,mkreq->client_key_pem_path ,-ret);
	   return -1;
       }
       MK_LOG(LOG_INFO,"%s(Success) Loading client_key.pem certificate file=%s \n ",__func__,mkreq->client_key_pem_path);
    } else {
       if (mkreq->pem_client_key_data_source == PEM_KEY_SRC_EMBED_FILES) {
	  // PEM_KEY_SRC_EMBED_FILES
          // Client key pem data
#ifdef ENABLE_BUILDTIME_EMBED_CLIENT_KEY_PEM_FILE
	  mkreq->client_key_pem_buf = (uint8_t *)client_key_pem_start;
          mkreq->client_key_pem_bytes = (client_key_pem_end-client_key_pem_start); 

	  MK_LOG(LOG_DEBUG ,"%s(PEM_KEY_SRC_EMBED_FILES) client_key_pem_bytes=%d strlen(client_key_pem_bytes)=%d \n", 
                   __func__,mkreq->client_key_pem_bytes,(int)strlen((char *)mkreq->client_key_pem_bytes));
#else
         MK_LOG(LOG_ALERT, "ALERT: %s() PEM_KEY_SRC_EMBED_FILES option for pem_client_key_data_source is not supported ...\n",__func__);
         MK_LOG(LOG_ALERT, "ALERT: #define ENABLE_BUILDTIME_EMBED_CLIENT_KEY_PEM_FILE at build time to enable it. \n");
         return -1;
#endif
       }
       if (!mkreq->client_key_pem_buf) {
	   MK_LOG(LOG_ERR,"%s(Error) empty certificate pem data bufffers: ca_cert, client_cert, clinet_key \n",__func__);
	   return -1;
       }
       slen = (int)strlen((char *)mkreq->client_key_pem_buf);
       if (mkreq->client_key_pem_bytes == slen) {
          // need to include the length of terminating null bytes when mbedtls_x509_crt_parse for parsing
          // pem data in a buffer
          //NOTE: In the case of embedded file as buffer the terminating null character is included already.
          mkreq->client_key_pem_bytes += 1;
          MK_LOG(LOG_NOTICE , "%s() adding an extra byte for the terminating null byte to client_key_pem_bytes\n",__func__);
       }
       // ---------------------- client_key ----------------------
       ret = mbedtls_pk_parse_key(&pmtls->x509_pkey, mkreq->client_key_pem_buf, mkreq->client_key_pem_bytes, NULL, 0);
       if (ret < 0) {
	   MK_LOG(LOG_ERR,"%s(Error) mbedtls_x509_crt_parse err loading client_key.pem bytes=%d ret=-%x \n ",
		      __func__,mkreq->client_key_pem_bytes,-ret);
	   return -1;
       }
       MK_LOG(LOG_INFO,"%s(Success) Loading client_key.pem certificate...len=%d \n ",__func__,mkreq->client_key_pem_bytes);

    }
    //-----------------------  DONE loading client_key ----------------------
    return 0 ;
}

int mk_tls_ssl_free(mk_tls_https_info *pmkctx)
{
    mk_mbedtls_conn_params *pmtls = &pmkctx->mtlsc;

    if (!pmkctx) {
       return -1;
    }
    pmtls = &pmkctx->mtlsc;
    mbedtls_net_free(&pmtls->net_sd);
    mbedtls_x509_crt_free(&pmtls->x509_clicert);
    mbedtls_x509_crt_free(&pmtls->x509_cacert);
    mbedtls_pk_free(&pmtls->x509_pkey);
    mbedtls_ssl_free(&pmtls->ssl_ctx);
    mbedtls_ssl_config_free(&pmtls->ssl_conf);
    mbedtls_ctr_drbg_free(&pmtls->ctr_drbg_ctx);
    mbedtls_entropy_free(&pmtls->entropy_ctx);
    return 0;
}

#define USER_AGENT "mimik"
int mk_prepare_send_https_request(mk_tls_https_info *pmkctx)
{
   int ret = 0;
   int sent = 0;
   mk_mbedtls_conn_params *pmtls = &pmkctx->mtlsc;
   mk_https_req *mkreq = &pmkctx->mkrequest;
   static const char * httpReqFmt = "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n";  //fill only https_path not full uri

  // prepare a very simple https GET request with given ip:port/path
   memset(pmkctx->txbuf,0,TX_HTTPS_BUF_SZ);

   snprintf((char *)pmkctx->txbuf, TX_HTTPS_BUF_SZ-1, httpReqFmt,
                    mkreq->https_path, mkreq->CN_hostname, USER_AGENT);  //fill only https_path not full uri

   pmkctx->txlen = strlen((const char *)pmkctx->txbuf);

   // send the data to peer node using ssl_ctx
   do {
	 ret = mbedtls_ssl_write(&pmtls->ssl_ctx, &pmkctx->txbuf[sent], pmkctx->txlen-sent);
	 if (ret >= 0) {
	     MK_LOG(LOG_DEBUG,"%s() mbedtls_ssl_write: sent=%d ret=%d txlen=%d \n",
                            __func__,sent,ret,pmkctx->txlen);
	     sent += ret;
	 } else if ((ret != MBEDTLS_ERR_SSL_WANT_WRITE) && (ret != MBEDTLS_ERR_SSL_WANT_READ)) {
	     MK_LOG(LOG_ERR,"%s() error mbedtls_ssl_write. sent=%d ret= -0x%x\n",__func__,sent,-ret);
	     return -1;
	 }
     } while(sent < pmkctx->txlen);
     MK_LOG(LOG_INFO,"%s() mbedtls_ssl_write: successfully sent=%d bytes ret=%d txlen=%d \n",
                            __func__,sent,ret,pmkctx->txlen);
    return sent;
}

long int mk_get_elaspedms(struct timeval *ptstart)
{
   long int elapsedms = 0;
   struct timeval cur_t = {0};
   if (!ptstart) {
       return 0;
   }
   gettimeofday(&cur_t, NULL);
   elapsedms = ((cur_t.tv_usec - ptstart->tv_usec)/1000) +
		       (cur_t.tv_sec - ptstart->tv_sec)*1000;
   return elapsedms;
}

// MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY : The peer notified us that the connection is going to be closed.
// MBEDTLS_ERR_SSL_WANT_READ         : No data of requested type currently available on underlying transport
// returns <=0 on error or failure to receive any data
// returns > 0 on successful data recpetion
int mk_recv_https_response(mk_tls_https_info *pmkctx)
{
   int ret = 0;
   int rc = 0;
   int len = RX_HTTPS_BUF_SZ-1;
   int rxBytes = 0;
   struct timeval tstart = {0,0};
   mk_mbedtls_conn_params *pmtls = &pmkctx->mtlsc;
   unsigned int ori_task_priority = 0;
   unsigned int cur_task_priority = 0;

   memset(pmkctx->rxbuf,0,RX_HTTPS_BUF_SZ);
   // pmkctx->rxbuf[0] = 0 ;
   pmkctx->rxlen = 0;

   ori_task_priority = uxTaskPriorityGet(NULL);
   MK_LOG(LOG_NOTICE,"%s() Try changing task priority from(%u) -> to(%u) \n",
                                   __func__,ori_task_priority,tskIDLE_PRIORITY);
   vTaskPrioritySet(NULL, tskIDLE_PRIORITY);
   MK_LOG(LOG_NOTICE,"%s() Task Prioirty after the change = %u \n",__func__, uxTaskPriorityGet(NULL));

   MK_LOG(LOG_INFO,"%s() Entry \n",__func__);

   gettimeofday(&tstart, NULL);
   while (len > 0) {

      ret = mbedtls_ssl_read(&pmtls->ssl_ctx, &pmkctx->rxbuf[rxBytes], len);
      if (ret > 0) {
	      rxBytes += ret;
	      len -= ret;
	      pmkctx->rxlen = rxBytes;
      } else {
	 if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
	    MK_LOG(LOG_DEBUG,"%s() MBEDTLS_ERR_SSL_WANT_READ/WRITE, ret=-0x%x rxlen=%d \n",__func__,-ret,rxBytes);
	    continue;
	 }
	 else if (ret == 0) {
	    MK_LOG(LOG_INFO,"%s() ret=0 and rxlen=%d read end of the underlying transport was closed \n",__func__,rxBytes);
	    pmkctx->rxlen = rxBytes;
	    break;
	 }
	 else if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
	    pmkctx->rxlen = rxBytes;
	    MK_LOG(LOG_INFO,"%s() MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY, ret=-0x%x rxlen=%d \n",__func__,ret,rxBytes);
	    break;
	 }
	 else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            long int elapsedms = mk_get_elaspedms(&tstart);

	    //MK_LOG(LOG_DEBUG,"%s() mbedtls_ssl_read MBEDTLS_ERR_SSL_TIMEOUT ret=-0x%x, elapsedms=%ld, timeoutms=%d rxlen=%d\n",
            //                    __func__,-ret,elapsedms,pmkctx->timeoutms,rxBytes);

            if ((elapsedms > pmkctx->timeoutms) && (pmkctx->timeoutms > 0)) {
	       MK_LOG(LOG_ERR,"%s() mbedtls_ssl_read : returning MBEDTLS_ERR_SSL_TIMEOUT ret=-0x%x, elapsedms=%ld > timeoutms=%d\n",
                                __func__,-ret,elapsedms,pmkctx->timeoutms);
	       pmkctx->rxlen = 0;
	       rc = -1;
	       break;
            }

	    // SSL_READ_SUBTIMEOUT_MS timeout during mbedtls_ssl_read and got
	    // MBEDTLS_ERR_SSL_TIMEOUT err.  Now, will use this opputunity to
	    // yeild to cpu and also reset the freeRTOS system watchdog.
            //vTaskDelay(1);
	    continue;
	 }
	 pmkctx->rxlen = 0;
	 rc = -1;
	 break;
    }

  } //end of while

  //try to revert the task priority to original value reagrdless of the result of above call.
  cur_task_priority = uxTaskPriorityGet(NULL);
  if (cur_task_priority !=  ori_task_priority) {
     vTaskPrioritySet(NULL, ori_task_priority);
     MK_LOG(LOG_NOTICE,"%s() Reverted back task priority from(%u) -> to(%u)\n",
                            __func__, cur_task_priority, uxTaskPriorityGet(NULL));
  }

  MK_LOG(LOG_INFO,"%s() Leave ret=%d rxBytes=%d rxlen=%d rc=%d \n",__func__,ret,rxBytes,pmkctx->rxlen,rc);
  pmkctx->rxbuf[pmkctx->rxlen] = 0; //terminate with in anycase for easier string operation later
  return rc == 0?pmkctx->rxlen:rc;

}

char * mk_get_https_content_data(unsigned char *rx_msg, int rx_len, int *pcontent_length)
{
   long int httpsz = 0 ;
   long int content_len = -1 ;
   char * contentref = NULL ;
   char * http_endseq = NULL ;
   char * mstart = NULL ;
   char * datastart = NULL ;

   if ((!rx_msg) || (rx_len <= 0) || (!pcontent_length)) {
      MK_LOG(LOG_ERR,"%s() : Invalid param \n",__func__);
      return NULL ;
   }

   mstart = (char *)rx_msg;

   http_endseq = strstr(mstart,"\r\n\r\n");
   if (!http_endseq) {
      MK_LOG(LOG_ERR,"%s() HTTP end is missing \n",__func__);
      return NULL;
   }

   httpsz = ((long int)http_endseq - (long int)mstart) + 4 ; // + 4 due to "\r\n\r\n"

   contentref = strstr(mstart, "Content-Length:");
   if (contentref) {
      if (sscanf(contentref,"Content-Length: %ld",&content_len) > 0) {
         MK_LOG(LOG_DEBUG,"%s() Content-Length = %ld \n",__func__,content_len);

         if((rx_len - httpsz) < content_len) {
            return NULL;
         }
      }
   }
   else {
      MK_LOG(LOG_INFO,"%s() Content-Length: is absent.\n",__func__);
   }

   if ((content_len > 0 ) && (rx_len > httpsz)) {
     datastart = http_endseq + 4 ;
     *pcontent_length = (int)content_len;
     MK_LOG(LOG_DEBUG,"%s() dataLen=%d, httpsz=%ld rx_len=%d content_len=%ld\n",
              __func__,strlen(datastart),httpsz,rx_len,content_len);
   }

   return datastart;
}

int mk_prepare_tls_ssl_ctx(mk_tls_https_info *pmkctx)
{
    int ret = 0;
    mk_mbedtls_conn_params *pmtls = &pmkctx->mtlsc;
    mk_https_req *mkreq = &pmkctx->mkrequest;
    unsigned int ori_task_priority = 0;
    unsigned int cur_task_priority = 0;

    MK_LOG(LOG_INFO,"%s() Entry ..... \n",__func__);

    //NOTE: The order of calling these _init function does not matter as they
    //only individually initializes them and most often memset mbedtls structure members.

    mbedtls_ssl_init(&pmtls->ssl_ctx);
    //SSL/TLS configuration to be shared between mbedtls_ssl_context structures.
    mbedtls_ssl_config_init(&pmtls->ssl_conf);
    //init crt_drbg: Counter mode Deterministic Random Byte Generator
    mbedtls_ctr_drbg_init(&pmtls->ctr_drbg_ctx);
    // init the entropy context
    mbedtls_entropy_init(&pmtls->entropy_ctx);
    //init net_sd
    mbedtls_net_init(&pmtls->net_sd);

    //init the structures that hold keys and certificates.
    mbedtls_x509_crt_init(&pmtls->x509_cacert);
    mbedtls_x509_crt_init(&pmtls->x509_clicert);
    mbedtls_pk_init(&pmtls->x509_pkey);

    // seed is a string of bits that is used as input to a DRBG mechanism
    // entropy is the randomness collected
    MK_LOG(LOG_DEBUG,"%s() Seeding the Counter mode Deterministic Random Byte Generator for entropy. \n",__func__);
    //Acquire seed prior to the generation of pseudorandom output bits by the DRBG.
    ret = mbedtls_ctr_drbg_seed(&pmtls->ctr_drbg_ctx, mbedtls_entropy_func, &pmtls->entropy_ctx, NULL, 0);
    if (ret != 0) {
        MK_LOG(LOG_ERR,"%s() mbedtls_ctr_drbg_seed() failed, error ret=0x%x \n",__func__, -ret);
        return -1;
    }

    ori_task_priority = uxTaskPriorityGet(NULL);
    MK_LOG(LOG_NOTICE,"%s() Try changing task priority from(%u) -> to(%u) \n",
                                   __func__,ori_task_priority,tskIDLE_PRIORITY);
    vTaskPrioritySet(NULL, tskIDLE_PRIORITY);
    MK_LOG(LOG_NOTICE,"%s() Task Prioirty after the change = %u \n",__func__, uxTaskPriorityGet(NULL));

    ret = mk_load_pem_certifcates(mkreq, pmtls);

    //try to revert the task priority to original value reagrdless of the result of above call.
    cur_task_priority = uxTaskPriorityGet(NULL);
    if (cur_task_priority !=  ori_task_priority) {
       vTaskPrioritySet(NULL, ori_task_priority);
       MK_LOG(LOG_NOTICE,"%s() Reverted back task priority from(%u) -> to(%u)\n",
                            __func__, cur_task_priority, uxTaskPriorityGet(NULL));
    }

    // check the return value - ret from above mk_load_pem_certifcates() call.
    if (ret < 0) {
        MK_LOG(LOG_ERR,"%s() error mk_load_pem_certifcates failed  \n ",__func__);
        return -1;
    }

    MK_LOG(LOG_INFO,"%s() Setting CN hostname(%s) for TLS session... \n ",__func__,mkreq->CN_hostname);

    // Use CN_hostname instead of connection hostname to match common name of server certificate
    ret = mbedtls_ssl_set_hostname(&pmtls->ssl_ctx, mkreq->CN_hostname);
    if (ret != 0) {
        MK_LOG(LOG_ERR,"%s() error mbedtls_ssl_set_hostname for %s returned -0x%x \n", __func__,mkreq->CN_hostname,-ret);
        return -1;
    }

    MK_LOG(LOG_DEBUG,"%s() set ssl_conf with CLIENT-endpoint, TRANSPORT_STREAM and PRESET_DEFAULT\n",__func__);

    ret = mbedtls_ssl_config_defaults(&pmtls->ssl_conf, MBEDTLS_SSL_IS_CLIENT, 
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        MK_LOG(LOG_ERR,"%s() error mbedtls_ssl_config_defaults returned -0x%x \n", __func__,-ret);
        return -1;
    }

    //NOTE: Set MBEDTLS_SSL_VERIFY_OPTIONAL verification of SSL certificate common name(CN)
    //to avoid mismatch of CN with the one registered by us, to proceed with connect.
    mbedtls_ssl_conf_authmode(&pmtls->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    // populate the default callback for getting (pseudo-)random numbers with drbg context
    mbedtls_ssl_conf_rng(&pmtls->ssl_conf, mbedtls_ctr_drbg_random, &pmtls->ctr_drbg_ctx);

    // populate ssl_conf with x509_cacert certificate data
    mbedtls_ssl_conf_ca_chain(&pmtls->ssl_conf, &pmtls->x509_cacert, NULL);

    // Append client certificate and client key context to ssl_conf
    ret = mbedtls_ssl_conf_own_cert(&pmtls->ssl_conf, &pmtls->x509_clicert, &pmtls->x509_pkey);
    if (ret < 0) {
       MK_LOG(LOG_ERR,"%s() error mbedtls_ssl_conf_own_cert returned -0x%x\n\n", __func__, -ret);
       return -1;
    }

    if (pmkctx->read_subtimeout_ms > 0) {
       MK_LOG(LOG_INFO,"%s() given timeoutms=%d read_subtimeout_ms=%d \n",
                                __func__,pmkctx->timeoutms,pmkctx->read_subtimeout_ms);
       mbedtls_ssl_conf_read_timeout(&pmtls->ssl_conf, pmkctx->read_subtimeout_ms);
    }

    // assign the populated entire ssl_conf to ssl_ctx
    ret = mbedtls_ssl_setup(&pmtls->ssl_ctx, &pmtls->ssl_conf);
    if (ret != 0) {
       MK_LOG(LOG_ERR,"%s() error mbedtls_ssl_setup returned -0x%x \n", __func__,-ret);
       return -1;
    }

    MK_LOG(LOG_INFO,"%s() Return ..... \n",__func__);
    return 0;
}

int mimik_tls_https_client_req_rsp(mk_https_req *preq, mk_response_data *prspd)
{
    int ret = 0;
    mk_tls_https_info *pmkctx = &mk_ctx;
    mk_mbedtls_conn_params *pmtls = &pmkctx->mtlsc;
    mk_https_req *mkreq = &pmkctx->mkrequest;
    char portstr[6] = {0};
    struct timeval tstart = {0,0};
    int loopcount=0;

    MK_LOG(LOG_INFO,"%s() Entry ..... \n",__func__);

    if ((!preq) || (!prspd) || (!preq->https_hostname)) {
      MK_LOG(LOG_ERR,"%s() mcfg invalid or null param \n",__func__);
      return -1;
    }

    // memcpy given mk_https_req preq into our mkreq, so that we could populate
    // default values in to our copy, for members whose values were not given
    // by the user -- to avoid changing the user given reference.

    memcpy(mkreq, preq, sizeof(mk_https_req));

    if (mkreq->timeoutsec <= 0) {
       mkreq->timeoutsec = DFT_HTTPS_TIMEOUT_SEC;
    }
    // timeoutms is used to enforce maximum time taken for tls handshake and recv operations
    pmkctx->timeoutms = mkreq->timeoutsec * 1000;

    // set read subtimeout to help TLS handshake and recv to timeout early with
    // error and upon which, will use the opportunity to yield to cpu and also
    // reset the freeRTOS system watchdog.
    pmkctx->read_subtimeout_ms = SSL_READ_SUBTIMEOUT_MS;

    // MK_LOG(LOG_INFO,"%s() recv_timeoutms = %d millisec, subtimeout_ms=%d  \n", 
    // __func__, pmkctx->timeoutms,pmkctx->read_subtimeout_ms);

    if (!mkreq->CN_hostname) {
       //mkreq->CN_hostname = preq->https_hostname;
       mkreq->CN_hostname = DFT_CERTIFICATION_COMMON_NAME_HOST;
    }
    if (!mkreq->https_path) {
       //mkreq->https_path = PATH_SLASH;
       mkreq->https_path = PATH_TENANTS_ME_SERVICES;
    }
    if (mkreq->port == 0) {
       mkreq->port = DFT_HTTPS_PORT;
    }

    //NOTE: The order of calling these _init function does not matter as they
    //only individually initializes them and most often memset mbedtls structure members.
    ret = mk_prepare_tls_ssl_ctx(pmkctx);
    if (ret != 0) {
       MK_LOG(LOG_ERR,"%s() error mk_prepare_tls_ssl_ctx \n", __func__);
       mk_tls_ssl_free(pmkctx);
       return -1;
    }

    MK_LOG(LOG_INFO,"%s() Connecting to %s:%hu...\n", __func__, mkreq->https_hostname, mkreq->port);

    // Newtork Transport Layer TCP/IP socket endpoint connection to peer tuple.
    sprintf(portstr,"%hu",mkreq->port);
    ret = mbedtls_net_connect(&pmtls->net_sd, mkreq->https_hostname, portstr, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
       MK_LOG(LOG_ERR,"%s() error mbedtls_net_connect failed and returned -%x\n",__func__,-ret);
       mk_tls_ssl_free(pmkctx);
       return -1;
    }
    MK_LOG(LOG_INFO,"%s() Connected to %s:%hu using TCP/IP\n", __func__, mkreq->https_hostname, mkreq->port);

    ret = mbedtls_net_set_block(&pmtls->net_sd);
    if (ret != 0) {
       MK_LOG(LOG_ERR,"%s() error mbedtls_net_set_block failed and returned -%x\n",__func__,-ret);
    }

    if (pmkctx->read_subtimeout_ms > 0) {
      //set context for I/O operations with timeout -- mbedtls_net_recv_timeout
       mbedtls_ssl_set_bio(&pmtls->ssl_ctx, &pmtls->net_sd, mbedtls_net_send,
                              mbedtls_net_recv, mbedtls_net_recv_timeout);
       MK_LOG(LOG_INFO,"%s() ssl_set_bio called with mbedtls_net_recv_timeout, %d milliseconds \n", 
                __func__, pmkctx->read_subtimeout_ms);
    }
    else {
       //set the context for I/O operations
       mbedtls_ssl_set_bio(&pmtls->ssl_ctx, &pmtls->net_sd, mbedtls_net_send, mbedtls_net_recv, NULL);
    }

    gettimeofday(&tstart, NULL);
    MK_LOG(LOG_INFO,"%s() Initiate TLS/SSL handshake .....  start.tv_sec=%lu start.tv_usec=%lu \n",
                              __func__,tstart.tv_sec,tstart.tv_usec);
    while ((ret = mbedtls_ssl_handshake(&pmtls->ssl_ctx)) != 0) {
      loopcount++;
      // retry only if the errors are MBEDTLS_ERR_SSL_WANT_READ , MBEDTLS_ERR_SSL_WANT_WRITE or MBEDTLS_ERR_SSL_TIMEOUT
      if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {

            long int elapsedms = mk_get_elaspedms(&tstart);
            //char errbuf[128] = {0};
            //mbedtls_strerror(ret, errbuf, sizeof(errbuf));
	    //MK_LOG(LOG_DEBUG,"%s() HANDSHAKE_TIMEOUT: MBEDTLS_ERR_SSL_TIMEOUT ret=-0x%x, elapsedms=%ld, timeoutms=%d\n erbuf=%s \n",
            //                    __func__,-ret,elapsedms,pmkctx->timeoutms,errbuf);

            if ((elapsedms > pmkctx->timeoutms) && (pmkctx->timeoutms > 0)) {
	       MK_LOG(LOG_ERR,"%s() HANDSHAKE_TIMEOUT: returning MBEDTLS_ERR_SSL_TIMEOUT ret=-0x%x, elapsedms=%ld > timeoutms=%d\n",
                                __func__,-ret,elapsedms,pmkctx->timeoutms);
               mk_tls_ssl_free(pmkctx);
               return -1;
            }

	    // SSL_READ_SUBTIMEOUT_MS timeout during TLS handshake and got
	    // MBEDTLS_ERR_SSL_TIMEOUT err.  Now, will use this opputunity to
	    // yeild to cpu and also reset the freeRTOS system watchdog.
            //vTaskDelay(1);

	    continue;
      }
      else if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
         MK_LOG(LOG_ERR,"%s() error mbedtls_ssl_handshake returned -0x%x\n", __func__, -ret);
         mk_tls_ssl_free(pmkctx);
         return -1;
      }
       MK_LOG(LOG_DEBUG,"%s() vTaskDelay-2 loopcount=%d\n",__func__,loopcount);
    }
    MK_LOG(LOG_NOTICE,"%s() TLS/SSL handshake success elapsedms=%ld loopcount=%d\n",__func__,mk_get_elaspedms(&tstart),loopcount);

    // verify certificate after handshake and log if any error
    ret = mbedtls_ssl_get_verify_result(&pmtls->ssl_ctx);
    if (ret != 0) {
      //Enable the following to get more details and return -1 if needed, 
      //based on additional error, such as CN mismatch with server certificate:

      // static char vbuf[512] = {0};
      // memset(vbuf,0,sizeof(vbuf));
      // mbedtls_x509_crt_verify_info(vbuf, sizeof(vbuf), " Err: ", ret);
      // MK_LOG(LOG_ERR,"%s() Verifying of peer X.509 certificate has error:\n   %s \n",__func__,vbuf);
    }
    else {
       MK_LOG(LOG_NOTICE,"%s() Verification of peer X.509 certificate is ok. \n",__func__);
    }

   // prepare and send a simplest https request message to peer node using established ssl_ctx
    ret = mk_prepare_send_https_request(pmkctx);
    if (ret < 0) {
       MK_LOG(LOG_ERR,"%s() error mk_prepare_send_https_request failed \n",__func__);
       mk_tls_ssl_free(pmkctx);
       return -1;
    }
    MK_LOG(LOG_INFO,"%s() ret=%d mk_prepare_send_https_request finished \n",__func__,ret);

    ret = mk_recv_https_response(pmkctx);
    if (ret <= 0) {
       MK_LOG(LOG_ERR,"%s() ret=%d mk_recv_https_response finished possibly with error, pmkctx->rxlen=%d \n",__func__,ret,pmkctx->rxlen);
    }
    else {
       MK_LOG(LOG_NOTICE,"%s() ret=%d mk_recv_https_response finished successfully pmkctx->rxlen=%d \n", __func__,ret,pmkctx->rxlen);

       //MK_LOG(LOG_DEBUG, "\n\nReceived Bytes[rxlen=%d, strlen=%d]: \n %s\n",pmkctx->rxlen,(int)strlen((const char *)pmkctx->rxbuf),pmkctx->rxbuf);

       if (prspd && prspd->rsp_buff && (prspd->rsp_max_buff_sz > 1)) {
          //for now copy the result as it is and upto only given size
          // parse and copy only https data and update content_length
          int tolen = pmkctx->rxlen < prspd->rsp_max_buff_sz ? pmkctx->rxlen:prspd->rsp_max_buff_sz - 1;
          char * pdata = NULL;
          pmkctx->content_length = 0;
          pdata = mk_get_https_content_data(pmkctx->rxbuf, pmkctx->rxlen, &pmkctx->content_length);
          if (pdata && (pmkctx->content_length > 0) && (pdata > (char *)pmkctx->rxbuf) && 
              (pmkctx->content_length < pmkctx->rxlen)) {

              MK_LOG(LOG_INFO,"%s() received data content_length=%d \n",__func__,pmkctx->content_length);
              memcpy(prspd->rsp_buff,pdata,pmkctx->content_length);
              prspd->rsp_buff[pmkctx->content_length] = 0;
              prspd->rsp_rx_bytes = pmkctx->content_length;
          }
          else {
              memcpy(prspd->rsp_buff,pmkctx->rxbuf,tolen);
              prspd->rsp_buff[tolen] = 0;
              prspd->rsp_rx_bytes = tolen;
          }
       }
    }

    mbedtls_ssl_close_notify(&pmtls->ssl_ctx);
    mk_tls_ssl_free(pmkctx);
    return pmkctx->rxlen;

}

#endif
