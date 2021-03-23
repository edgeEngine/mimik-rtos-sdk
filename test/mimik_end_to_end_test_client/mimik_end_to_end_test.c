/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File:   mimik_acme_client_test.c
 *  Author: Varadhan Venkataseshan
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"

#include "mimik_acme_client.h"
#include "mimik_edge_services.h"

int mk_test_end_to_end_client_main(void *parg);
static void mimik_end_to_end_test_task(void *parg);

//#define MK_TEST_NODE_ID "_mk-v12-4996e4c2442cc796f2c0ddb4e5e1627d._tcp.local"
#define MK_TEST_NODE_ID "_mk-v13-4996e4c2442cc796f2c0ddb4e5e1627d._tcp.local"

#define ACME_DIRECTORY_URL "http://192.168.1.74:8088/acme/v2/directory"
#define MK_ACME_DFT_KID_ACCOUNT_URL "http://localhost:8088/acme/v2/accounts/vvkmimik2020"

int mk_test_end_to_end_client_main(void *parg)
{
   int rc = 0;
   // acme certifcate related variables:
   esp_err_t ret = ESP_OK;
   static mk_acme_config acfg = { 0 } ; // need not be static, but ok,
   unsigned char mac_addr[8] = {0};
   static char mac_addr_str[20] = {0};  //need to be static due to limite stack size
   static mk_acme_certificate acerts;   //need to be static due to limite stack size

   // edge super node and service discovery related variables:
   static mk_edge_service_record srec;  //need to be static due to limited stack size
   #define RXBUFSZ_15K 15360
   static char rxbuf[RXBUFSZ_15K+1] = {0}; //need to be static due to limited stack size
   static mk_edge_service_config scfg; // need not be static , but ok

   if (!parg) {
      printf("\n%s() acme_client <client_id> not given \n",__func__);
      return -1;
   }

   /**********  STEP1: Obtain client certifcate from acme server  *******/

   // DO NOT use custom as it fetched from BLK3 that may not be set by user.
   //Return base MAC address which was previously written to BLK3 of EFUSE.
   //ret = esp_efuse_mac_get_custom(mac_addr);

   //Return base MAC address which is factory-programmed by Espressif in BLK0 of EFUSE.
   ret = esp_efuse_mac_get_default(mac_addr);
   if (ret != ESP_OK) {
      printf("esp_efuse_mac_get_default error (%s)", esp_err_to_name(ret));
   }else {
      printf("esp_efuse_mac_get_default success \n");
      snprintf(mac_addr_str, sizeof(mac_addr_str), "%02x:%02x:%02x:%02x:%02x:%02x",
         mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
      printf("esp_efuse_mac_get_default value = %s \n",mac_addr_str);
   }

   printf("\n%s() Starting full end to end testing ...\n",__func__);
   memset(&acfg,0,sizeof(acfg));
   memset(&acerts,0,sizeof(acerts));

   // The following are mandatory parameters
   acfg.acme_directory_url = ACME_DIRECTORY_URL;
   acfg.acme_account_url = MK_ACME_DFT_KID_ACCOUNT_URL;
   acfg.acme_pem_acct_key_data_source = ACME_PEM_KEY_SRC_EMBED_FILES;
   acfg.acct_key_passphrase = "mimik";
   acfg.acct_key_passphrase_len = strlen(acfg.acct_key_passphrase);

   // fill device_id, client_id and scope for order identification.
   acfg.device_id = (strlen(mac_addr_str)>0)?mac_addr_str:"device_id1";
   acfg.client_id = (char *)parg;
   acfg.scope = "edge:clusters:clientservice";
   printf("%s() calling mimik_acme_client_obtain_certificate with device_id=%s client_id=%s \n",__func__,acfg.device_id,acfg.client_id);

   rc = mimik_acme_client_obtain_certificate(&acfg, &acerts);
   if ( rc < 0 ) {
     printf("%s(): Error rc=%d \n",__func__,rc);
   }

   if (acerts.cert_pem_len > 0) {
      printf("\n%s() Received Certificate(length=%d), as it is: \n%s\n\n",__func__,acerts.cert_pem_len,acerts.certificate_pem);
   } else {
      printf("\n%s() error received cert_pem_len is 0 \n",__func__);
      return -1;
   }

   if (acerts.pri_key_pem_len > 0) {
      printf("\n%s() Private Key(length=%d): \n%s\n\n",__func__,acerts.pri_key_pem_len,acerts.pri_key_pem);
   } else {
      printf("\n%s() error received pri_key_pem_len is 0 \n",__func__);
      return -1;
   }

   /**********  STEP2: edge super node and service discovery *******/
   printf("\n%s() calling mimik_edge_service_discovery ...\n",__func__);
   memset(&scfg,0,sizeof(mk_edge_service_config)); 
   scfg.node_type_id = MK_TEST_NODE_ID;

   scfg.pem_ca_cert_data_source = PEM_SER_KEY_SRC_EMBED_FILES;

   scfg.pem_client_key_data_source = PEM_SER_KEY_SRC_BUF;
   scfg.client_key_pem_buf = (unsigned char *)acerts.pri_key_pem;
   scfg.client_key_pem_bytes = acerts.pri_key_pem_len;

   scfg.pem_client_cert_data_source = PEM_SER_KEY_SRC_BUF;
   scfg.client_cert_pem_buf = (unsigned char *)acerts.certificate_pem;
   scfg.client_cert_pem_bytes = acerts.cert_pem_len;

   memset(rxbuf,0,sizeof(rxbuf));
   srec.ser_rsp_max_buff_sz = RXBUFSZ_15K;
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

   return 0;
}

static void mimik_end_to_end_test_task(void *parg)
{
    mk_test_end_to_end_client_main(parg);

    vTaskDelete(NULL);
}

void mimik_end_to_end_client_test(void *parg)
{
    xTaskCreate(&mimik_end_to_end_test_task, "mimik_end_to_end_test_task", 8192, parg, 5, NULL);
}
