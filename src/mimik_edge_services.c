/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File: mimik_edge_services.c
 *  Author: Varadhan Venkataseshan
 */

#if !defined(__linux__)

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mk_mdns_client.h"
#include "mk_tls_https_request.h"
#include "mimik_edge_services.h"
#include "mk_services_data.h"
#include "cJSON.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_http_client.h"
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

static char g_log_lvl = LOG_NOTICE;

//JSON service records parsing helper functions to get c structured members from
// received JSON service record objects.
static int mimik_json_parse_service_records(mk_edge_service_record * mk_ser_rec);
static int mk_json_get_number_item_value(const cJSON * jsrc, char *name, unsigned short int *pout);
static int mk_json_get_string_item_value(const cJSON * jsrc, char *name, char **ppout);
static int mk_json_parse_data_array_service_records(__data *pref, cJSON *jdata, int index);
static int mk_json_parse_addresses_records(__address *pref, cJSON *jdata, int index);
static int mk_json_parse_attributes_records(__attributes *pref, cJSON *jdata, int index);
static int mk_json_parse_characteristics_records(__characteristics *pref, cJSON *jdata, int index);
static int mk_json_parse_services_records(__services *pref, cJSON *jdata, int index);

//http://localhost:8083/.well-known/node-configuration
typedef struct mk_nodecfg_response_data {
   char *rsp_buff;   // buffer to fill the response
   int  rsp_max_buff_sz;  // max size of the buffer
   int  rsp_rx_bytes;  // actual received bytes
   int  content_length; // length mentioned in http content_length
}mk_nodecfg_response_data;

typedef struct nodecfg_json {
    void *jroot;  //root pointer of parsed JSON object.
    //{"sslPort":8084}
    unsigned short int sslPort;
}nodecfg_json;

typedef struct mk_http_nodecfg {

  unsigned short int port; //server port
  char *http_hostname; // ipv4 or hostname string
  #define DFT_HTTP_NODE_PATH "/.well-known/node-configuration"
  char *http_path; // HTTP Path, if not set, default is `/`

  char *http_url; // full url http://hostname:port/path HTTP Path, if not set, default is `/`

  char *set_Host;   // for http header - "Host" 
  char *set_UserAgent;  // for http header - "User-Agent"

  #define DFT_HTTPS_NODECFG_IMEOUT_SEC  120
  int timeoutsec;

} mk_http_nodecfg;


typedef struct mk_nodecfg_info {
#define RXBUFSZ_1K  1024
   char rxbuf[RXBUFSZ_1K+1];
   mk_http_nodecfg hCfg;
   struct mk_nodecfg_response_data mkrspdata;
   nodecfg_json nodecfgdoc;
   unsigned short int ssl_service_port;
}mk_nodecfg_info;

static int mk_esp_http_nodecfg_req_rsp(struct mk_http_nodecfg *mkcfg, struct mk_nodecfg_response_data *mkrsp);
static int mk_get_node_configuration(mk_nodecfg_info *nctx);
static int mk_json_parse_nodecfg(char *databuff, nodecfg_json *dr);
static int mk_set_esp_http_cfg(esp_http_client_config_t *ecfg, mk_http_nodecfg *mkcfg);
static int mk_free_nodecfg_json(nodecfg_json *nr);
esp_err_t mk_nodecfg_http_event_handler(esp_http_client_event_t *evt);

int mimik_edge_service_discovery(mk_edge_service_config *mk_ser_cfg, mk_edge_service_record * mk_ser_rec)
{
   int rc = 0;
   int rcount = 0;
   static mk_mdns_sn_record snreply;

   static mk_https_req sreq;
   static mk_response_data srsp;
   static mk_nodecfg_info snodecfg;
   unsigned short int ssl_service_port = 0;

   if ((!mk_ser_cfg) || (!mk_ser_cfg->node_type_id) || (!mk_ser_rec) ||
       (!mk_ser_rec->ser_rsp_buff) || (mk_ser_rec->ser_rsp_max_buff_sz == 0)) {
      MK_LOG(LOG_ERR,"%s() Error, invalid parameters \n",__func__);
      return -1;
   }

   //Step1-mdns-udp: Discover mimik edge Supernode
   #define MAX_RET_SN_DISCOVERY 5
   for (rcount = 1; rcount <= MAX_RET_SN_DISCOVERY; rcount++) {
      memset(&snreply,0,sizeof(mk_mdns_sn_record));
      rc = mimik_mdns_discover_supernode_client(mk_ser_cfg->node_type_id, mk_ser_cfg->if_ipv4,
							    &snreply, mk_ser_cfg->max_timeoutsec);
      if (rc < 0) {
	 MK_LOG(LOG_ERR ,"%s() mimik_mdns_discover_supernode_client failed: rcount=%d times, retrying ... \n",__func__,rcount);
         continue;
      }
      break;
   }

   if (rc < 0) {
      MK_LOG(LOG_ERR,"%s() Error, call to mimik_mdns_discover_supernode_client failed : rcount=%d times \n",__func__,rcount);
      return -1;
   }

   //Step2 GET .well-known/node-configuration
   // For now .well-known/node-configuration gets the sslPort to connect to service discovery server.
   memset(&snodecfg,0,sizeof(snodecfg));
   snodecfg.hCfg.http_hostname = snreply.snIpStr;
   snodecfg.hCfg.port = snreply.snPort;
   snodecfg.hCfg.http_path = DFT_HTTP_NODE_PATH;

   rc = mk_get_node_configuration(&snodecfg);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(2): mk_get_node_configuration failed \n",__func__);
   }

   if (snodecfg.ssl_service_port > 0) {
       MK_LOG(LOG_NOTICE, "%s(2): GET node configuration service port = %u\n",__func__,snodecfg.ssl_service_port);
       ssl_service_port = snodecfg.ssl_service_port;
   } else {
       ssl_service_port = DFT_HTTPS_PORT;
       MK_LOG(LOG_DEBUG, "%s(2): Using default port for service request = %u \n",__func__,DFT_HTTPS_PORT);
   }

   //Step3-https-tcp: GET service details from discovered mimik edge Supernode.
   memset(&sreq,0,sizeof(mk_https_req));
   memset(&srsp,0,sizeof(mk_response_data));

   // Populate mk_https_req members and mk_response_data result buffer before invoking service discovery
   sreq.port = ssl_service_port;
   sreq.https_hostname = snreply.snIpStr;
   sreq.https_path = PATH_TENANTS_ME_SERVICES;

   //specific for ca_cert
   sreq.pem_ca_cert_data_source = mk_ser_cfg->pem_ca_cert_data_source;
   //specific for client_key
   sreq.pem_client_key_data_source = mk_ser_cfg->pem_client_key_data_source;
   //specific for client_cert
   sreq.pem_client_cert_data_source = mk_ser_cfg->pem_client_cert_data_source ;

   sreq.ca_cert_pem_path = mk_ser_cfg->ca_cert_pem_path;
   sreq.ca_cert_pem_buf = mk_ser_cfg->ca_cert_pem_buf;
   sreq.ca_cert_pem_bytes = mk_ser_cfg->ca_cert_pem_bytes;

   sreq.client_key_pem_path = mk_ser_cfg->client_key_pem_path;
   sreq.client_key_pem_buf = mk_ser_cfg->client_key_pem_buf;
   sreq.client_key_pem_bytes = mk_ser_cfg->client_key_pem_bytes;

   sreq.client_cert_pem_path = mk_ser_cfg->client_cert_pem_path;
   sreq.client_cert_pem_buf = mk_ser_cfg->client_cert_pem_buf;
   sreq.client_cert_pem_bytes = mk_ser_cfg->client_cert_pem_bytes;

   sreq.timeoutsec = mk_ser_cfg->max_timeoutsec;

   memset(mk_ser_rec->ser_rsp_buff,0,mk_ser_rec->ser_rsp_max_buff_sz);
   srsp.rsp_buff = mk_ser_rec->ser_rsp_buff;
   srsp.rsp_max_buff_sz = mk_ser_rec->ser_rsp_max_buff_sz;

    rc = mimik_tls_https_client_req_rsp(&sreq, &srsp);
    if (rc < 0) {
      MK_LOG(LOG_ERR,"%s() Error, call to mimik_tls_https_client_req_rsp failed \n",__func__);
      return -1;
    }

   //Step4-copy the results obtained from mimik edge Supernode device.
   strncpy((char *)mk_ser_rec->sn_Name,(char *)snreply.sn_Name,S_MAX_SZ);
   strncpy((char *)mk_ser_rec->sn_Txt,(char *)snreply.sn_Txt,S_MAX_SZ);
   strncpy((char *)mk_ser_rec->snIpStr,(char *)snreply.snIpStr,sizeof(mk_ser_rec->snIpStr));
   mk_ser_rec->snPort = snreply.snPort;
   mk_ser_rec->ssl_service_port = ssl_service_port;
   mk_ser_rec->ser_rsp_rx_bytes = srsp.rsp_rx_bytes;
   // ser_rsp_buff already got filled

   mimik_json_parse_service_records(mk_ser_rec);

   MK_LOG(LOG_DEBUG,"sn_Name: %s \n sn_Txt: %s \n snIpStr: %s \n snPort: %hu \n "
                    "ser_rsp_rx_bytes: %d \n ser_rsp_buff: %s \n",
                   mk_ser_rec->sn_Name,mk_ser_rec->sn_Txt,mk_ser_rec->snIpStr,mk_ser_rec->snPort,
                   mk_ser_rec->ser_rsp_rx_bytes,mk_ser_rec->ser_rsp_buff);

   return 0;
}

//mimik_json_parse_service_records() parses the content of the string databuff contnet as
//JSON object to equivalent c struct and places the result in service_records
//structure members.
//returns 0 on success and -1 on failure
int mimik_json_parse_service_records(mk_edge_service_record * mk_ser_rec)
{
   char *databuff = NULL;
   service_records *sr = NULL;
   cJSON *jroot = NULL;
   cJSON *jdata = NULL;
   char *name = NULL;
   int rc = 0;

   if (!mk_ser_rec) {
      return -1;
   }

   if (mk_ser_rec->jroot != NULL) {
      MK_LOG(LOG_ERR,"%s() mk_ser_rec->jroot=%p is not empty, may have been parsed already \n",__func__,mk_ser_rec->jroot);
      MK_LOG(LOG_ERR,"%s() call mimik_free_service_records( ) to free old jroot values \n",__func__);
      return -1;
   }

   databuff = mk_ser_rec->ser_rsp_buff;
   sr = &mk_ser_rec->srd;

   jroot = cJSON_Parse(databuff);
   if (!jroot) {
      return -1;
   }
   mk_ser_rec->jroot = jroot;

   MK_LOG(LOG_INFO,"%s() sizeof(service_records)=%d \n",__func__,(int)sizeof(service_records));

   //"type"
    name = "type";
    rc = mk_json_get_string_item_value(jroot,name,&sr->type);
    if (rc == 0) {
        MK_LOG(LOG_DEBUG,"%s() name(%s) => (addr=%p):value(%s) \n ",__func__,name,sr->type,sr->type);
    }

    //"type": "data" //array of data items.
    sr->data_array_count = 0;
    name = "data";
    jdata = cJSON_GetObjectItemCaseSensitive(jroot, name);

    if (jdata && cJSON_IsArray(jdata)) {
       int i = 0;
       int asz = cJSON_GetArraySize(jdata);
       if (asz > MAX_DATA_ARRAY_COUNT) {
	  MK_LOG(LOG_NOTICE,"%s() GetArraySize(%s) = %d > maxsz=%d \n",__func__,name,asz,MAX_DATA_ARRAY_COUNT);
	  asz = MAX_DATA_ARRAY_COUNT;
       }

       for (i = 0; (i < asz); i++) {
	  rc = mk_json_parse_data_array_service_records(&sr->data[sr->data_array_count], jdata, i);
	  if (rc == 0) {
	      sr->data_array_count++;
	      MK_LOG(LOG_DEBUG,"%s() %s array parsing success: i=%d array_count=%d asz=%d\n",
				__func__,name,i,sr->data_array_count,asz);
	  }
       } //end of for data array processing
    }

   return 0;
}

static int mk_json_parse_data_array_service_records(__data *pref, cJSON *jdata, int index)
{
   cJSON *jobject = NULL;
   cJSON *jiarray = NULL;
   cJSON *jitem = NULL;
   char *objname = NULL;
   char **ppout = NULL;
   char *name = NULL;
   int rc = 0;
   int asz = 0;
   int i = 0;

   if ((!pref)||(!jdata)||(!cJSON_IsArray(jdata))) {
      MK_LOG(LOG_ERR,"%s() Invalid param \n ",__func__);
      return -1;
   }

   jiarray = cJSON_GetArrayItem(jdata,index);
   if (!jiarray) {
     MK_LOG(LOG_ERR,"%s() Unable to get array object at index=%d \n ",__func__,index);
     return -1;
   }

   objname = "account";
   jobject = cJSON_GetObjectItemCaseSensitive(jiarray, objname);
   if (jobject && cJSON_IsObject(jobject)) {
      //get id and self
      name = "id";
      ppout = &pref->account.id;
      rc = mk_json_get_string_item_value(jobject, name, ppout);
      if ((rc == 0) && (*ppout)) {
        MK_LOG(LOG_DEBUG,"%s() objname(%s) => name(%s) => value(%s) \n ",__func__,objname,name,*ppout);
      }
      name = "self";
      ppout = &pref->account.self;
      rc = mk_json_get_string_item_value(jobject, name, ppout);
      if ((rc == 0) && (*ppout)) {
        MK_LOG(LOG_DEBUG,"%s() objname(%s) => name(%s) => value(%s) \n ",__func__,objname,name,*ppout);
      }
   }

   //"addresses":[array]
   pref->address_array_count = 0;
   name = "addresses";
   jobject = cJSON_GetObjectItemCaseSensitive(jiarray, name);
   if (jobject && cJSON_IsArray(jobject)) {
      asz = cJSON_GetArraySize(jobject);
      if (asz > MAX_ADDRESS_ARRAY_COUNT) {
	MK_LOG(LOG_NOTICE,"%s() GetArraySize(%s) = %d > maxsz=%d \n",__func__,name,asz,MAX_ADDRESS_ARRAY_COUNT);
	asz = MAX_ADDRESS_ARRAY_COUNT;
      }

      for (i = 0; (i < asz);  i++) {
	 rc = mk_json_parse_addresses_records(&pref->addresses[pref->address_array_count], jobject, i);
	 if (rc == 0) {
	     pref->address_array_count++;
	     MK_LOG(LOG_DEBUG,"%s() %s array parsing success: i=%d array_count=%d asz=%d\n",
			       __func__,name,i,pref->address_array_count,asz);
	 }
      } //end of for addresses array processing
   }

   //"attributes":[array]
   pref->attributes_array_count = 0;
   name = "attributes";
   jobject = cJSON_GetObjectItemCaseSensitive(jiarray, name);
   if (jobject && cJSON_IsArray(jobject)) {
      asz = cJSON_GetArraySize(jobject);
      if (asz > MAX_ATTRIBUTES_ARRAY_COUNT) {
	MK_LOG(LOG_NOTICE,"%s() GetArraySize(%s) = %d > maxsz=%d \n",__func__,name,asz,MAX_ATTRIBUTES_ARRAY_COUNT);
	asz = MAX_ATTRIBUTES_ARRAY_COUNT;
      }

      for (i = 0; (i < asz);  i++) {
	 rc = mk_json_parse_attributes_records(&pref->attributes[pref->attributes_array_count], jobject, i);
	 if (rc == 0) {
	     pref->attributes_array_count++;
	     MK_LOG(LOG_DEBUG,"%s() %s array parsing success: i=%d array_count=%d asz=%d\n",
			       __func__,name,i,pref->attributes_array_count,asz);
	 }
      } //end of for attributes array processing
   }

   //"characteristics":[array]
   pref->characteristics_array_count = 0;
   name = "characteristics";
   jobject = cJSON_GetObjectItemCaseSensitive(jiarray, name);
   if (jobject && cJSON_IsArray(jobject)) {
      asz = cJSON_GetArraySize(jobject);
      if (asz > MAX_CHARACTERISTICS_ARRAY_COUNT) {
	MK_LOG(LOG_NOTICE,"%s() GetArraySize(%s) = %d > maxsz=%d \n",__func__,name,asz,MAX_CHARACTERISTICS_ARRAY_COUNT);
	asz = MAX_CHARACTERISTICS_ARRAY_COUNT;
      }

      for (i = 0; (i < asz);  i++) {
	 rc = mk_json_parse_characteristics_records(&pref->characteristics[pref->characteristics_array_count], jobject, i);
	 if (rc == 0) {
	     pref->characteristics_array_count++;
	     MK_LOG(LOG_DEBUG,"%s() %s array parsing success: i=%d array_count=%d asz=%d\n",
			       __func__,name,i,pref->characteristics_array_count,asz);
	 }
      } //end of for characteristics array processing
   }

   //"createdAt"
   name = "createdAt";
   ppout = &pref->createdAt;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"id"
   name = "id";
   ppout = &pref->id;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"localLinkNetworkId"
   name = "localLinkNetworkId";
   ppout = &pref->localLinkNetworkId;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"location": object - array:
   objname = "location";
   jobject = cJSON_GetObjectItemCaseSensitive(jiarray, objname);
   if (jobject && cJSON_IsObject(jobject)) {
      cJSON * jtmp = NULL ;
      name = "coordinates";
      jtmp = cJSON_GetObjectItemCaseSensitive(jobject, name);
      if (jtmp && cJSON_IsArray(jtmp)) {
           jitem = cJSON_GetArrayItem(jtmp,0);
           if (cJSON_IsNumber(jitem)) {
                pref->location.coordinates[0] = jitem->valuedouble;
           }
           jitem = cJSON_GetArrayItem(jtmp,1);
           if (cJSON_IsNumber(jitem)) {
                pref->location.coordinates[1] = jitem->valuedouble;
           }
           MK_LOG(LOG_DEBUG,"%s() objname(%s) => name(%s) => values(%f, %f) \n ",
                   __func__,objname,name,pref->location.coordinates[0],pref->location.coordinates[1]);
      }
      //get origin and type
      name = "origin";
      ppout = &pref->location.origin;
      rc = mk_json_get_string_item_value(jobject, name, ppout);
      if ((rc == 0) && (*ppout)) {
        MK_LOG(LOG_DEBUG,"%s() objname(%s) => name(%s) => value(%s) \n ",__func__,objname,name,*ppout);
      }
      name = "type";
      ppout = &pref->location.type;
      rc = mk_json_get_string_item_value(jobject, name, ppout);
      if ((rc == 0) && (*ppout)) {
        MK_LOG(LOG_DEBUG,"%s() objname(%s) => name(%s) => value(%s) \n ",__func__,objname,name,*ppout);
      }
   }

   //"networkAddress"
   name = "networkAddress";
   ppout = &pref->networkAddress;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"rolesInCluster": - 1 element array: get first element
   name = "rolesInCluster";
   jobject = cJSON_GetObjectItemCaseSensitive(jiarray, name);
   if (jobject && cJSON_IsArray(jobject)) {
       jitem = cJSON_GetArrayItem(jobject,0);
       if (jitem) {
           pref->rolesInCluster = cJSON_GetStringValue(jitem);
           MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,pref->rolesInCluster?pref->rolesInCluster:"");
       }
   }

   //"self"
   name = "self";
   ppout = &pref->self;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"services":[array]
   pref->services_array_count = 0;
   name = "services";
   jobject = cJSON_GetObjectItemCaseSensitive(jiarray, name);
   if (jobject && cJSON_IsArray(jobject)) {
      asz = cJSON_GetArraySize(jobject);
      if (asz > MAX_SERVICES_ARRAY_COUNT) {
	MK_LOG(LOG_NOTICE,"%s() GetArraySize(%s) = %d > maxsz=%d \n",__func__,name,asz,MAX_SERVICES_ARRAY_COUNT);
	asz = MAX_SERVICES_ARRAY_COUNT;
      }

      for (i = 0; (i < asz);  i++) {
	 rc = mk_json_parse_services_records(&pref->services[pref->services_array_count], jobject, i);
	 if (rc == 0) {
	     pref->services_array_count++;
	     MK_LOG(LOG_DEBUG,"%s() %s array parsing success: i=%d array_count=%d asz=%d\n",
			       __func__,name,i,pref->services_array_count,asz);
	 }
      } //end of for services array processing
   }

   //"tenant": - object:
   //"tenant:id"
   //"tenant:self"
   objname = "tenant";
   jobject = cJSON_GetObjectItemCaseSensitive(jiarray, objname);
   if (jobject && cJSON_IsObject(jobject)) {
      //"id"
      name = "id";
      ppout = &pref->tenant.id;
      rc = mk_json_get_string_item_value(jobject, name, ppout);
      if ((rc == 0) && (*ppout)) {
        MK_LOG(LOG_DEBUG,"%s() objname(%s) => name(%s) => value(%s) \n ",__func__,objname,name,*ppout);
      }

      //"self"
      name = "self";
      ppout = &pref->tenant.self;
      rc = mk_json_get_string_item_value(jobject, name, ppout);
      if ((rc == 0) && (*ppout)) {
        MK_LOG(LOG_DEBUG,"%s() objname(%s) => name(%s) => value(%s) \n ",__func__,objname,name,*ppout);
      }
   }

   //"updatedAt"
   name = "updatedAt";
   ppout = &pref->updatedAt;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   return 0;
}

static int mk_json_parse_addresses_records(__address *pref, cJSON *jdata, int index)
{
   cJSON *jobject = NULL;
   cJSON *jiarray = NULL;
   char *objname = NULL;
   char **ppout = NULL;
   char *name = NULL;
   int rc = 0;

   if ((!pref)||(!jdata)||(!cJSON_IsArray(jdata))) {
      MK_LOG(LOG_ERR,"%s() Invalid param \n ",__func__);
      return -1;
   }

   jiarray = cJSON_GetArrayItem(jdata,index);
   if (!jiarray) {
     MK_LOG(LOG_ERR,"%s() Unable to get array object at index=%d \n ",__func__,index);
     return -1;
   }

   //"type"
   name = "type";
   ppout = &pref->type;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"url:href"
   objname = "url";
   jobject = cJSON_GetObjectItemCaseSensitive(jiarray, objname);
   if (jobject && cJSON_IsObject(jobject)) {
      //"href"
      name = "href";
      ppout = &pref->url.href;
      rc = mk_json_get_string_item_value(jobject, name, ppout);
      if ((rc == 0) && (*ppout)) {
        MK_LOG(LOG_DEBUG,"%s() objname(%s) => name(%s) => value(%s) \n ",__func__,objname,name,*ppout);
      }
   }

   //"routingPort"
   name = "routingPort";
   rc = mk_json_get_number_item_value(jiarray,name,&pref->routingPort);
   if (rc == 0) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%d) \n ",__func__,name,pref->routingPort);
   }

   return 0;
}

int mk_json_parse_attributes_records(__attributes *pref, cJSON *jdata, int index)
{
   cJSON *jiarray = NULL;
   char **ppout = NULL;
   char *name = NULL;
   int rc = 0;

   if ((!pref)||(!jdata)||(!cJSON_IsArray(jdata))) {
      MK_LOG(LOG_ERR,"%s() Invalid param \n ",__func__);
      return -1;
   }

   jiarray = cJSON_GetArrayItem(jdata,index);
   if (!jiarray) {
     MK_LOG(LOG_ERR,"%s() Unable to get array object at index=%d \n ",__func__,index);
     return -1;
   }

   //"name"
   name = "name";
   ppout = &pref->name;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"value"
   name = "value";
   ppout = &pref->value;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   return 0;
}

int mk_json_parse_characteristics_records(__characteristics *pref, cJSON *jdata, int index)
{
   cJSON *jiarray = NULL;
   char **ppout = NULL;
   char *name = NULL;
   int rc = 0;

   if ((!pref)||(!jdata)||(!cJSON_IsArray(jdata))) {
      MK_LOG(LOG_ERR,"%s() Invalid param \n ",__func__);
      return -1;
   }

   jiarray = cJSON_GetArrayItem(jdata,index);
   if (!jiarray) {
     MK_LOG(LOG_ERR,"%s() Unable to get array object at index=%d \n ",__func__,index);
     return -1;
   }

   //"name"
   name = "name";
   ppout = &pref->name;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"value"
   name = "value";
   ppout = &pref->value;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   return 0;
}

int mk_json_parse_services_records(__services *pref, cJSON *jdata, int index)
{
   cJSON *jobject = NULL;
   cJSON *jiarray = NULL;
   char *objname = NULL;
   char **ppout = NULL;
   char *name = NULL;
   int rc = 0;

   if ((!pref)||(!jdata)||(!cJSON_IsArray(jdata))) {
      MK_LOG(LOG_ERR,"%s() Invalid param \n ",__func__);
      return -1;
   }

   jiarray = cJSON_GetArrayItem(jdata,index);
   if (!jiarray) {
     MK_LOG(LOG_ERR,"%s() Unable to get array object at index=%d \n ",__func__,index);
     return -1;
   }

   //"id"
   name = "id";
   ppout = &pref->id;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"self"
   name = "self";
   ppout = &pref->self;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"serviceType"
   name = "serviceType";
   ppout = &pref->serviceType;
   rc = mk_json_get_string_item_value(jiarray,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"tenant:id"
   //"tenant:self"
   objname = "tenant";
   jobject = cJSON_GetObjectItemCaseSensitive(jiarray, objname);
   if (jobject && cJSON_IsObject(jobject)) {
      //"id"
      name = "id";
      ppout = &pref->tenant.id;
      rc = mk_json_get_string_item_value(jobject, name, ppout);
      if ((rc == 0) && (*ppout)) {
        MK_LOG(LOG_DEBUG,"%s() objname(%s) => name(%s) => value(%s) \n ",__func__,objname,name,*ppout);
      }

      //"self"
      name = "self";
      ppout = &pref->tenant.self;
      rc = mk_json_get_string_item_value(jobject, name, ppout);
      if ((rc == 0) && (*ppout)) {
        MK_LOG(LOG_DEBUG,"%s() objname(%s) => name(%s) => value(%s) \n ",__func__,objname,name,*ppout);
      }
   }

   return 0;
}

static int mk_json_get_number_item_value(const cJSON * jsrc, char *name, unsigned short int *pout)
{
   cJSON *jitem = NULL;
   if ((!jsrc) || (!pout) ||(!name)) {
     return -1;
   }
   jitem = cJSON_GetObjectItemCaseSensitive(jsrc, name);
   if (cJSON_IsNumber(jitem)) {
        unsigned short int num = (unsigned short int)jitem->valuedouble;
        *pout = num;
        //MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%hu) \n ",name,num);
        return 0;
   }
   return -1;
}

int mk_json_get_string_item_value(const cJSON * jsrc, char *name, char **ppout)
{
   cJSON *jitem = NULL;
   if ((!jsrc) || (!ppout) ||(!name)) {
     return -1;
   }
   jitem = cJSON_GetObjectItemCaseSensitive(jsrc, name);
   if (cJSON_IsString(jitem) && (jitem->valuestring != NULL)) {
        *ppout = jitem->valuestring;
        //MK_LOG(LOG_DEBUG,"%s() name(%s) => (addr=%p):value(%s) \n ",name,*ppout,*ppout);
        return 0;
   }
   return -1;
}

int mimik_free_service_records(mk_edge_service_record * mk_ser_rec)
{
   if (mk_ser_rec && mk_ser_rec->jroot) {
      memset(&mk_ser_rec->srd,0,sizeof(service_records));
      cJSON_Delete((cJSON *)mk_ser_rec->jroot);
      mk_ser_rec->jroot = NULL;
   }
   return 0;
}

void mimik_print_service_records(mk_edge_service_record * mk_ser_rec)
{
  service_records *sr = NULL;
  int n =0;
  int i = 0; 

  if ((!mk_ser_rec) || (!mk_ser_rec->jroot)) {
     printf("%s() entry jroot is empty , return\n",__func__);
     return;
  }

  sr = &mk_ser_rec->srd;

  printf("\n ------------------------------ service records ------------------------------- \n");
  if (sr->type) {
     printf("\t type \t => \t %s \n ",sr->type);
  }

  for (n = 0; n < sr->data_array_count ; n++) {

  printf("\n\n Begin data[%d] : { \n",n);

    if (sr->data[n].account.id) {
	printf("\t data.account.id \t => \t %s \n ",sr->data[n].account.id);
    }
    if (sr->data[n].account.self) {
	printf("\t data.account.self \t => \t %s \n ",sr->data[n].account.self);
    }

    //"addresses":
    for (i = 0; i < sr->data[n].address_array_count ; i++) {
       if (sr->data[n].addresses[i].routingPort > 0) {
	 printf("\t data.addresses[%d].routingPort \t => \t %hu \n ",i,sr->data[n].addresses[i].routingPort);
       }
       if (sr->data[n].addresses[i].type) {
         printf("\t data.addresses[%d].type \t => \t %s \n ",i,sr->data[n].addresses[i].type);
       }
       if (sr->data[n].addresses[i].url.href) {
	 printf("\t data.addresses[%d].url.href \t => \t %s \n ",i,sr->data[n].addresses[i].url.href);
       }
    }

    //"attributes":
    for (i = 0; i < sr->data[n].attributes_array_count; i++) {
       if (sr->data[n].attributes[i].name) {
         printf("\t data.attributes[%d].name\t => \t %s \n ",i,sr->data[n].attributes[i].name);
       }
       if (sr->data[n].attributes[i].value) {
         printf("\t data.attributes[%d].value \t => \t %s \n ",i,sr->data[n].attributes[i].value);
       }
    }

    //"characteristics":
    for (i = 0; i < sr->data[n].characteristics_array_count; i++) {
       if (sr->data[n].characteristics[i].name) {
         printf("\t data.characteristics[%d].name\t => \t %s \n ",i,sr->data[n].characteristics[i].name);
       }
       if (sr->data[n].characteristics[i].value) {
         printf("\t data.characteristics[%d].value \t => \t %s \n ",i,sr->data[n].characteristics[i].value);
       }
    }

    //"createdAt":
    if (sr->data[n].createdAt) {
	printf("\t data.createdAt \t => \t %s \n ",sr->data[n].createdAt);
    }

    //"id":
    if (sr->data[n].id) {
	printf("\t data.id \t => \t %s \n ",sr->data[n].id);
    }

    //"localLinkNetworkId":
    if (sr->data[n].localLinkNetworkId) {
	printf("\t data.localLinkNetworkId \t => \t %s \n ",sr->data[n].localLinkNetworkId);
    }

    //"location":
    if (sr->data[n].location.coordinates[0] || sr->data[n].location.coordinates[1]) {
	printf("\t data.location.coordinates\t => \t %f , %f \n ",
                 sr->data[n].location.coordinates[0],sr->data[n].location.coordinates[1]);
    }
    if (sr->data[n].location.origin) {
	printf("\t data.location.origin\t => \t %s \n ",sr->data[n].location.origin);
    }
    if (sr->data[n].location.type) {
	printf("\t data.location.type\t => \t %s \n ",sr->data[n].location.type);
    }

    //"networkAddress":
    if (sr->data[n].networkAddress) {
	printf("\t data.networkAddress \t => \t %s \n ",sr->data[n].networkAddress);
    }

    //"rolesInCluster":
    if (sr->data[n].rolesInCluster) {
	printf("\t data.rolesInCluster \t => \t %s \n ",sr->data[n].rolesInCluster);
    }

    //"self":
    if (sr->data[n].self) {
	printf("\t data.self \t => \t %s \n ",sr->data[n].self);
    }

    //"services":
    for (i = 0; i < sr->data[n].services_array_count; i++) {
       if (sr->data[n].services[i].id) {
         printf("\t data.services[%d].id\t => \t %s \n ",i,sr->data[n].services[i].id);
       }
       if (sr->data[n].services[i].self) {
         printf("\t data.services[%d].self \t => \t %s \n ",i,sr->data[n].services[i].self);
       }
       if (sr->data[n].services[i].serviceType) {
         printf("\t data.services[%d].serviceType \t => \t %s \n ",i,sr->data[n].services[i].serviceType);
       }
       if (sr->data[n].services[i].tenant.id) {
         printf("\t data.services[%d].tenant.id \t => \t %s \n ",i,sr->data[n].services[i].tenant.id);
       }
       if (sr->data[n].services[i].tenant.self) {
         printf("\t data.services[%d].tenant.self \t => \t %s \n ",i,sr->data[n].services[i].tenant.self);
       }
    }

    //"self":
    if (sr->data[n].tenant.id) {
	printf("\t data.tenant.id \t => \t %s \n ",sr->data[n].tenant.id);
    }
    if (sr->data[n].tenant.self) {
	printf("\t data.tenant.self \t => \t %s \n ",sr->data[n].tenant.self);
    }
    if (sr->data[n].updatedAt) {
	printf("\t data.updatedAt \t => \t %s \n ",sr->data[n].updatedAt);
    }

   printf("\n\n } End data[%d]  \n",n);

 } // end of for loop data array

}

static int mk_get_node_configuration(mk_nodecfg_info *nctx)
{
    int rc = 0;
    if (!nctx) {
       return -1;
    }

    nctx->hCfg.set_Host = nctx->hCfg.http_hostname?nctx->hCfg.http_hostname:"localhost";
    nctx->hCfg.set_UserAgent = "mimik";

    nctx->mkrspdata.rsp_buff = nctx->rxbuf;
    nctx->mkrspdata.rsp_max_buff_sz = sizeof(nctx->rxbuf);
    memset(nctx->rxbuf,0,sizeof(nctx->rxbuf));
    rc = mk_esp_http_nodecfg_req_rsp(&nctx->hCfg, &nctx->mkrspdata);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    nctx->mkrspdata.rsp_buff[nctx->mkrspdata.rsp_rx_bytes] = 0; //NULL terminate, just in case, to be used as a string buffer
    MK_LOG(LOG_INFO, "%s(): recvd rc=%d mkrspdata[rsp_rx_bytes=%d content_length=%d] \n",
                      __func__,rc,nctx->mkrspdata.rsp_rx_bytes,nctx->mkrspdata.content_length);

    //Parse JSON object and the obtain the values of sslPort
    rc = mk_json_parse_nodecfg(nctx->mkrspdata.rsp_buff, &nctx->nodecfgdoc);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    if (nctx->nodecfgdoc.sslPort > 0) {
      nctx->ssl_service_port = (unsigned short int)nctx->nodecfgdoc.sslPort;
    }
    mk_free_nodecfg_json(&nctx->nodecfgdoc);
    
    return 0;
}

int mk_esp_http_nodecfg_req_rsp(struct mk_http_nodecfg *mkcfg, struct mk_nodecfg_response_data *mkrsp)
{
   int rc = 0;
   int content_length = 0;
   int status_code = 0;
   esp_http_client_config_t espCfg = {0}; 
   esp_http_client_handle_t espclient = NULL;
   esp_err_t err = 0;
   char *hname = NULL;
   char *hval = NULL;

   rc = mk_set_esp_http_cfg(&espCfg, mkcfg);
   if (rc < 0) {
      MK_LOG(LOG_ERR,"%s() mk_set_esp_http_cfg failed.\n",__func__);
      return -1;
   }

   if (mkrsp && mkrsp->rsp_buff && (mkrsp->rsp_max_buff_sz > 0)) {
       mkrsp->rsp_rx_bytes = 0;
       mkrsp->content_length = 0;
       espCfg.user_data = (void *)mkrsp; // need to access in call to store data
   }

   espclient = esp_http_client_init(&espCfg);
   if (!espclient) {
      rc = -1;
      MK_LOG(LOG_ERR,"%s() esp_http_client_init failed \n",__func__);
      return -1;
   }

   if (mkcfg->set_UserAgent) {
      hname = "User-Agent";
      hval = mkcfg->set_UserAgent;
      err = esp_http_client_set_header(espclient, hname, hval);
      if (err != ESP_OK) {
         MK_LOG(LOG_ERR, "%s: set_header(%s:%s) error %d %s", __func__, hname,hval,err, esp_err_to_name(err));
      }
   }

   if (mkcfg->set_Host) {
      hname = "Host";
      hval = mkcfg->set_Host;
      err = esp_http_client_set_header(espclient, hname, hval);
      if (err != ESP_OK) {
         MK_LOG(LOG_ERR, "%s: set_header(%s:%s) error %d %s", __func__, hname,hval,err, esp_err_to_name(err));
      }
   }

   hname = "Connection";
   hval = "close";
   err = esp_http_client_set_header(espclient, hname, hval);
   if (err != ESP_OK) {
      MK_LOG(LOG_ERR, "%s: set_header(%s:%s) error %d %s", __func__, hname,hval,err, esp_err_to_name(err));
   }

   err = esp_http_client_perform(espclient);
   if (err == ESP_OK) {
	content_length = esp_http_client_get_content_length(espclient);
	status_code = esp_http_client_get_status_code(espclient);

        // first check status code : either 200 or 201 only for acme
        if ((status_code != 200) && (status_code != 201)) {
	   MK_LOG(LOG_INFO,"%s() HTTP acme error, Status = %d is not valid \n", __func__,status_code);
           rc = -1;
        }

        if (content_length > 0) {
	   MK_LOG(LOG_INFO,"%s() HTTP Status = %d, content_length = %d \n", __func__,status_code,content_length);
           rc = content_length;
        }
        else {
	   MK_LOG(LOG_INFO,"%s() HTTP Status = %d  \n", __func__,status_code);
           rc = 0;
        }

   } else {
      rc = -1;
      MK_LOG(LOG_ERR,"%s() esp_http_client_perform http request failed: err=%d  %s \n",
			 __func__,err,esp_err_to_name(err));
   }

   esp_http_client_close(espclient);
   esp_http_client_cleanup(espclient);

   return rc;
}

static int mk_set_esp_http_cfg(esp_http_client_config_t *ecfg, mk_http_nodecfg *mkcfg)
{
   if ((!ecfg) || (!mkcfg)) {
     MK_LOG(LOG_ERR,"%s() cfg null param \n",__func__);
     return -1;
   }

   if (mkcfg->http_url) {
      ecfg->url = mkcfg->http_url;
   }
   else if (mkcfg->http_hostname) {
      ecfg->host = mkcfg->http_hostname;
      ecfg->port = mkcfg->port;
      if (mkcfg->http_path) {
         ecfg->path = mkcfg->http_path;
      }
   }
   else {
     MK_LOG(LOG_ERR,"%s() empty url or hostname \n",__func__);
     return -1;
   }

   ecfg->method = HTTP_METHOD_GET;
   
   ecfg->event_handler = mk_nodecfg_http_event_handler;

   // plain http
   ecfg->transport_type = HTTP_TRANSPORT_OVER_TCP;

   if (mkcfg->timeoutsec <= 0) {
       mkcfg->timeoutsec = DFT_HTTPS_NODECFG_IMEOUT_SEC;
   }

   ecfg->timeout_ms = mkcfg->timeoutsec * 1000;

   return 0;
}

int mk_free_nodecfg_json(nodecfg_json *nr)
{
   if (nr && nr->jroot) {
      cJSON_Delete((cJSON *)nr->jroot);
      nr->jroot = NULL;
      memset(nr,0,sizeof(nodecfg_json));
   }
   return 0;
}

esp_err_t mk_nodecfg_http_event_handler(esp_http_client_event_t *evt)
{
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            MK_LOG(LOG_INFO, "%s() HTTP_EVENT_ERROR \n",__func__);
            break;
        case HTTP_EVENT_ON_HEADER:
            // MK_LOG(LOG_DEBUG, "%s() HTTP_EVENT_ON_HEADER, key=%s, value=%s \n", __func__,evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            MK_LOG(LOG_INFO, "%s() HTTP_EVENT_ON_DATA, len=%d \n", __func__,evt->data_len);
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // MK_LOG(LOG_DEBUG,"%s() data_len=%d \n", __func__,evt->data_len);
                if (evt->user_data) {
                    struct mk_nodecfg_response_data *rd = (struct mk_nodecfg_response_data *)evt->user_data;
                    if (rd->rsp_buff && (rd->rsp_max_buff_sz > (rd->rsp_rx_bytes + evt->data_len))) {
                          memcpy(&rd->rsp_buff[rd->rsp_rx_bytes], (char *)evt->data, evt->data_len);
                          rd->rsp_rx_bytes += evt->data_len;
                          rd->content_length = esp_http_client_get_content_length(evt->client);
                          MK_LOG(LOG_INFO,"%s() rsp_rx_bytes=%d content_length=%d data_len=%d \n",
                                    __func__,rd->rsp_rx_bytes, rd->content_length, evt->data_len);
                    }
                }
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            MK_LOG(LOG_DEBUG, "%s() HTTP_EVENT_ON_FINISH \n",__func__);
            break;
        case HTTP_EVENT_DISCONNECTED:
            MK_LOG(LOG_DEBUG, "%s() HTTP_EVENT_DISCONNECTED \n",__func__);
            break;
        default: 
            break;
    }
    return ESP_OK;
}

//returns 0 on success and -1 on failure
int mk_json_parse_nodecfg(char *databuff, nodecfg_json *nr)
{
   cJSON *jroot = NULL;
   char *name = NULL;
   int rc = 0;

   if ((!databuff) || (!nr)) {
      return -1;
   }

   if (nr->jroot != NULL) {
      MK_LOG(LOG_ERR,"%s() nr->jroot=%p is not empty, may have been parsed already \n",__func__,nr->jroot);
      mk_free_nodecfg_json(nr);
   }

   jroot = cJSON_Parse(databuff);
   if (!jroot) {
      return -1;
   }
   nr->jroot = jroot;

   //"sslPort"
    name = "sslPort";
    rc = mk_json_get_number_item_value(jroot,name,&nr->sslPort);
    if (rc == 0) {
        MK_LOG(LOG_NOTICE,"%s() name(%s) => value(%u) \n ",__func__,name,nr->sslPort);
    }

   return 0;
}

#endif
