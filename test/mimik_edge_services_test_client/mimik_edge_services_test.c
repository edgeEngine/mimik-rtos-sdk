/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File:   mimik_edge_services_test.c
 *  Author: Varadhan Venkataseshan
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mimik_edge_services.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

//#define MK_TEST_NODE_ID "_mk-v12-4996e4c2442cc796f2c0ddb4e5e1627d._tcp.local"
#define MK_TEST_NODE_ID "_mk-v13-4996e4c2442cc796f2c0ddb4e5e1627d._tcp.local"

void mimik_test_get_edge_services_task(void *parg)
{
   int i = 0 ;
   int rc = 0;
   static mk_edge_service_record srec;
   #define RXBUFSZ_10K 10240
   static char rxbuf[RXBUFSZ_10K+1] = {0};
   mk_edge_service_config scfg;
   
   printf("\n%s() Starting Testing mimik_get_edge_services ...\n",__func__);
   for (i = 1 ; i <= 5 ; i++) {

     // Fill mandatory parameters for testing.

     memset(&scfg,0,sizeof(mk_edge_service_config)); 
     scfg.node_type_id = MK_TEST_NODE_ID;
     scfg.pem_ca_cert_data_source = PEM_SER_KEY_SRC_EMBED_FILES;
     scfg.pem_client_key_data_source = PEM_SER_KEY_SRC_EMBED_FILES;
     scfg.pem_client_cert_data_source = PEM_SER_KEY_SRC_EMBED_FILES;

     memset(rxbuf,0,sizeof(rxbuf));
     srec.ser_rsp_max_buff_sz = RXBUFSZ_10K;
     // point test_rsp->rsp_buff to a valid buffer
     srec.ser_rsp_buff = rxbuf;

      rc = mimik_edge_service_discovery(&scfg, &srec);
      if (rc < 0) {
        printf("%s(): Error rc=%d \n",__func__,rc);
      }
      else {
        printf("\n\nsn_Name: %s \n sn_Txt: %s \n snIpStr: %s \n snPort: %hu \n "
                    "ser_rsp_rx_bytes: %d \n ser_rsp_buff: %s \n",
                   srec.sn_Name,srec.sn_Txt,srec.snIpStr,srec.snPort,
                   srec.ser_rsp_rx_bytes,srec.ser_rsp_buff);

        mimik_print_service_records(&srec);

        mimik_free_service_records(&srec);
      }
      printf("\n%s() Testing mimik_get_edge_services again in 20 seconds: round %d ....\n\n",__func__,i+1);
      sleep(20);
   }
   printf("\nFinished Testing mimik_get_edge_services %d times.\n\n",i);

   vTaskDelete(NULL);
}

void mimik_test_get_edge_services(void *parg)
{
    xTaskCreate(mimik_test_get_edge_services_task, "mimik_edge_services", 8192, NULL, tskIDLE_PRIORITY, NULL);
}
