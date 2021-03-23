/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File: mk_mdns_clinet_test.c
 *  Author: Varadhan Venkataseshan
 */

// TO compile : gcc -o mkclient ../src/*.c ./*.c -I ../include


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mk_mdns_client.h"

//#define MK_TEST_ID "_mk-v12-4996e4c2442cc796f2c0ddb4e5e1627d._tcp.local"
#define MK_TEST_ID "_mk-v13-4996e4c2442cc796f2c0ddb4e5e1627d._tcp.local"

#if defined(__linux__)
int main(void)
#else
int mkclient(void)
#endif
{
   int rc = 0;
   int i = 0;
   mk_mdns_sn_record sn_resp = {0};
   #define RX_TIMEOUT_SEC 3
   char *ipv4 = "";

   printf("\n Starting Testing mimik_mdns_discover_supernode_client ...\n");
   for( i=0; i < 10 ; i++) {
      rc = mimik_mdns_discover_supernode_client(MK_TEST_ID, ipv4, &sn_resp, RX_TIMEOUT_SEC);
      if ( rc > 0 ) {
        printf("main: recvd rc=%d \n",rc);
      }

      printf("\nTesting mimik_mdns_discover_supernode_client again in 10 seconds: round %d ....\n\n",i+1);
      sleep(10);
   }
   printf("\nFinished Testing mimik_mdns_discover_supernode_client %d times.\n\n",i);
   return 0;
}
