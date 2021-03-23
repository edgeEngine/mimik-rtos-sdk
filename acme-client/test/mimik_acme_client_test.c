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
#include "mimik_acme_client.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"

#include "mimik_acme_client.h"

int mk_test_acme_client_main(void *parg);

#define ACME_DIRECTORY_URL "http://192.168.1.74:8088/acme/v2/directory"
#define MK_ACME_DFT_KID_ACCOUNT_URL "http://localhost:8088/acme/v2/accounts/vvkmimik2020"

int mk_test_acme_client_main(void *parg)
{
   int rc = 0;
   int i = 0;
   mk_acme_config acfg = { 0 } ;
   esp_err_t ret = ESP_OK;
   unsigned char mac_addr[8] = {0};
   static char mac_addr_str[20] = {0};
   static mk_acme_certificate acerts;

   if (!parg) {
      printf("\n%s() acme_client <client_id> not given \n",__func__);
      return -1;
   }

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

   printf("\n%s() Starting Testing mimik_acme_client_obtain_certificate ...\n",__func__);
   for( i=0; i < 1 ; i++) {

      memset(&acfg,0,sizeof(acfg));
      memset(&acerts,0,sizeof(acerts));

      // The following are mandatory parameters
      acfg.acme_directory_url = ACME_DIRECTORY_URL;
      acfg.acme_account_url = MK_ACME_DFT_KID_ACCOUNT_URL;
      acfg.acme_pem_acct_key_data_source = ACME_PEM_KEY_SRC_EMBED_FILES;
      acfg.acct_key_passphrase = "mimik";
      acfg.acct_key_passphrase_len = strlen(acfg.acct_key_passphrase);

      // fill some dummy device_id, client_id and scope for order identification.
      acfg.device_id = (strlen(mac_addr_str)>0)?mac_addr_str:"device_id1";
      //acfg.client_id = "c8:f7:50:5c:46:b3";
      acfg.client_id = (char *)parg;
      acfg.scope = "edge:clusters:clientservice";
      printf("%s() running mimik_acme_client_obtain_certificate with device_id=%s client_id=%s \n",__func__,acfg.device_id,acfg.client_id);

      rc = mimik_acme_client_obtain_certificate(&acfg, &acerts);
      if ( rc < 0 ) {
        printf("%s(): Error rc=%d \n",__func__,rc);
      }

      if (acerts.cert_pem_len > 0) {
         printf("\n%s() Received Certificate(length=%d), as it is: \n%s\n\n",__func__,acerts.cert_pem_len,acerts.certificate_pem);
      }

      if (acerts.pri_key_pem_len > 0) {
         printf("\n%s() Private Key(length=%d): \n%s\n\n",__func__,acerts.pri_key_pem_len,acerts.pri_key_pem);
      }

      printf("\n%s() Testing mimik_acme_client_obtain_certificate again in 20 seconds: round %d ....\n\n",__func__,i+1);
      sleep(20);
   }
   printf("\nFinished Testing mimik_acme_client_obtain_certificate %d times.\n\n",i);
   return 0;
}

static void acme_client_test_task(void *parg)
{
    mk_test_acme_client_main(parg);

    vTaskDelete(NULL);
}

void mimik_test_acme_client(void *parg)
{
    xTaskCreate(&acme_client_test_task, "acme_client_test_task", 8192, parg, 5, NULL);
}
