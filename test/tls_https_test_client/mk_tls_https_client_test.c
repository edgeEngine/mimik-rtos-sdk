/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File:   mk_tls_https_client_test.c
 *  Author: Varadhan Venkataseshan
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mk_tls_https_request.h"

static void mk_test_tls_https_client_request(void *parg);

#define MKTEST_HTTPS_HOSTNAME "192.168.1.74"
#define MKTEST_HTTPS_PORT 4433
#define MKTEST_HTTPS_PATH "/tenants/me/services"

void mk_test_tls_https_client_request(void *parg)
{
   int i = 0 ;
   int rc = 0;
   static mk_https_req test_req ;
   static mk_response_data test_rsp ;
   #define RXBUFSZ_10K 10240
   static char rxbuf[RXBUFSZ_10K+1] = {0};
   
   printf("\n%s() Starting Testing mimik_tls_https_client_req_rsp ...\n",__func__);
   for (i = 1 ; i <= 10 ; i++) {

     // fill test values for test_req and test_rsp before callig mimik_tls_https_client_req_rsp
     test_req.https_hostname = MKTEST_HTTPS_HOSTNAME;
     test_req.port = MKTEST_HTTPS_PORT;
     test_req.https_path = MKTEST_HTTPS_PATH;
     test_req.pem_ca_cert_data_source = PEM_KEY_SRC_EMBED_FILES;
     test_req.pem_client_key_data_source = PEM_KEY_SRC_EMBED_FILES;
     test_req.pem_client_cert_data_source = PEM_KEY_SRC_EMBED_FILES;

     // point test_rsp->rsp_buff to a valid buffer
      memset(rxbuf,0,sizeof(rxbuf));
      test_rsp.rsp_max_buff_sz = RXBUFSZ_10K;
      test_rsp.rsp_buff = rxbuf;

      rc = mimik_tls_https_client_req_rsp(&test_req, &test_rsp);
      if (rc < 0) {
        printf("%s(): Error rc=%d \n",__func__,rc);
      }
      else {
        printf("%s(): recvd rc=%d rspdata[rsp_rx_bytes=%d] \n %s \n",
                          __func__,rc,test_rsp.rsp_rx_bytes,test_rsp.rsp_buff);
      }
      printf("\n%s() Testing mimik_tls_https_client_req_rsp again in 20 seconds: round %d ....\n\n",__func__,i+1);
      sleep(20);
   }
   printf("\nFinished Testing mimik_tls_https_client_req_rsp %d times.\n\n",i);
}
