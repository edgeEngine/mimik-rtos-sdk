/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File: mimik_acme_client.c
 *  Author: Varadhan Venkataseshan
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "cJSON.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_http_client.h"
#include "esp_err.h"  

#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"

#include "freertos/task.h"

#include "mimik_acme_client.h"

typedef struct mk_acme_http_config {

#define MK_PROTO_HTTPS 1
#define MK_PROTO_HTTP  0
  char  http_proto; //default is http

#define MK_HTTP_METHOD_GET  0
#define MK_HTTP_METHOD_HEAD 1
#define MK_HTTP_METHOD_POST 2
  char  http_method;

  unsigned short int port; //server port
  char *http_hostname; // ipv4 or hostname string 
  char *http_path; // HTTP Path, if not set, default is `/`

  char *http_url; // full url http://hostname:port/path HTTP Path, if not set, default is `/`

  #define MK_HTTP_SET_CONTENT_TYPE_JOSE_JSON "application/jose+json"
  char *set_Content_Type;   // for http header - "Content-Type"

  #define MK_HTTP_SET_HOST_LOCALHOST "localhost"
  char *set_Host;   // for http header - "Host" 

  #define MK_HTTP_SET_USER_AGENT_MIMIK "mimik"
  char *set_UserAgent;  // for http header - "User-Agent"

  #define MK_HTTP_SET_ACCEPT_PEM_CHAIN "application/pem-certificate-chain"
  char *set_Accept;  // for http header - "Accept"

  char *post_msg;  // pointer to the message to be posted.
  int  post_msg_len;

  #define DFT_HTTPS_TIMEOUT_SEC  120
  int timeoutsec;
  #define DFT_HTTPS_DFT_BUFFER_SZ 10240
  int buffer_size;              // HTTP buffer size (both send and receive)

} mk_acme_http_config;

typedef struct mk_acme_response_data {
   char *rsp_buff;   // buffer to fill the response
   int  rsp_max_buff_sz;  // max size of the buffer
   int  rsp_rx_bytes;  // actual received bytes
   int  content_length; // length mentioned in http content_length

   //acme specific response headers, may be move this mk_acme_info
   #define HEADER_ACME_REPLAY_NONCE "Replay-Nonce"
   //256 bytes should be enough
   #define NONCE_SZ 256
   char Replay_Nonce[NONCE_SZ+1];
   #define HEADER_ACME_LOCATION "location"
   #define LOCATION_SZ 512
   char location[LOCATION_SZ+1];
   int location_len;

}mk_acme_response_data;

typedef struct acme_directory {
    void *jroot;  //root pointer of parsed JSON object.
    char *newAccount;
    char *newNonce;
    char *newOrder;
    //char *revokeCert;
}acme_directory;

typedef struct acme_order_response {
    void *jroot;  //root pointer of parsed JSON object.
    char *status;
    char *finalize;
    char *authorizations; //We only need the first member of this array[ ] json item.
    char *orderId; //mimik's specific "orderId" exact string not in rf8555 fields
}acme_order_response;

typedef struct __challenges{
     char *url;
     char *type;
     char *status;
     char *token;
}__challenges;

typedef struct acme_authorizations_response {
     void *jroot;  //root pointer of parsed JSON object.
     char *status;
     __challenges challenges;
}acme_authorizations_response;

typedef struct acme_challenges_response {
     void *jroot;  //root pointer of parsed JSON object.
     __challenges challenges;
}acme_challenges_response;

typedef struct acme_finalize_response {
    void *jroot;  //root pointer of parsed JSON object.
    char *certificate;
    char *status;
}acme_finalize_response;

#define ACME_SERVER_HOSTNAME "192.168.1.74"
#define ACME_SERVER_PORT 8088
#define ACME_DIRECTORY_PATH "/acme/v2/directory"

#define ACME_RESOURCE_MSG_JSON_SPRINTF_FORMAT  "{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}"

#define ACME_PROTECTED_SPRINTF_FORMAT  "{\"url\":\"%s\",\"alg\":\"RS256\",\"nonce\":\"%s\",\"kid\":\"%s\"}"

#define ACME_PAYLOAD_MIMIK_ORDER_SPRINTF_FORMAT  "{\"identifiers\":[{\"type\":\"device\",\"value\":\"%s\"}]}"

/*

device_identifier = {
  "device_id": "ijojodsofds",
  "client_id": "ijosjofsjfs",
   "scope": "edge:clusters:clientservice"
}
value = base64url(device_identifier).device
*/
#define ACME_MIMIK_DEVICE_IDENTIFIER_SPRINTF_FORMAT "{\"device_id\":\"%s\",\"client_id\":\"%s\",\"scope\":\"%s\"}"

#define ACME_PAYLOAD_FINALIZE_CSR_SPRINTF_FORMAT "{\"csr\":\"%s\"}"

typedef struct acme_msg_format {

   #define MAX_SZ_1K 1024
   #define MAX_SZ_2K 2048
   #define MAX_SZ_3K 3072
   #define MAX_SZ_4K 4096
   #define MAX_SZ_5K 5120
   #define MAX_SZ_8K 8192

   //Assign sufficient buffer sizes for various message needs

   // txbuf is the data buffer used when sending data to acme server
   #define MAX_TX_BUF_SZ     MAX_SZ_4K
   char txbuf[MAX_TX_BUF_SZ+1];
   int  txlen;

   #define MAX_PROTECTED_SZ  MAX_SZ_1K
   char protected_str[MAX_PROTECTED_SZ+1];
   char protected_base64_str[MAX_PROTECTED_SZ+1];

   #define MAX_PAYLOAD_SZ    MAX_SZ_3K
   char payload_str[MAX_PAYLOAD_SZ+1];
   char payload_base64_str[MAX_PAYLOAD_SZ+1];

   #define MAX_SIGNATURE_SZ  MAX_SZ_1K
   char signature_base64[MAX_SIGNATURE_SZ+1];

   #define MAX_TMP_BUF_SZ    MAX_SZ_4K
   char temp_msg_buf[MAX_TMP_BUF_SZ+1];

   #define MAX_IDENTIFIER_BUF_SZ  512
   char identifier_value[MAX_IDENTIFIER_BUF_SZ+1]; //device_id, client_id, scope JSON prefix
   char identifierb64_value[MAX_IDENTIFIER_BUF_SZ+1]; //base64(identifier_value)
   //identifierb64_value_dot_device is the final full identifier used in order request and in CSR CN value
   char identifierb64_value_dot_device[MAX_IDENTIFIER_BUF_SZ+1]; //base64(identifier_value).device

   #define MAX_CHALLENGE_URI_LEN 1024
   char mk_challenge_url[MAX_CHALLENGE_URI_LEN]; //mimik specific challenge uri

}acme_msg_format;

typedef struct mk_mbedtls_key_params {

    // Counter mode Deterministic Random Byte Generator
    mbedtls_ctr_drbg_context ctr_drbg_ctx;

    // entropy is the randomness collected
    mbedtls_entropy_context entropy_ctx;

    // Account key, Certificate key
    mbedtls_pk_context acct_pkey;  // Account key
    mbedtls_pk_context cert_pkey;  // Certificate key pair

    char csr_cn_name[256]; //way more than enough
    #define CSR_DATA_SZ 4096
    unsigned char csrbuf[CSR_DATA_SZ];
    //pcsr = &csrbuf[CSR_DATA_SZ - csr_len] points to CSR data written by mebdtls function into csrbuf buffer
    unsigned char *pcsr; // points to CSR data written by mebdtls function into csrbuf buffer
    int csr_len;
    unsigned char csr_base64[CSR_DATA_SZ];
    int csr64_len;

}mk_mbedtls_key_params;

typedef struct mk_acme_info {
#define RXBUFSZ_8K  8192 
#define RXBUFSZ_10K 10240
#define RXBUFSZ   RXBUFSZ_8K
   char rxbuf[RXBUFSZ+1];
   char * kid_KeyId;  //URL obtained as a response to newAccount ACME request from server.
   acme_msg_format tx_msg;
   mk_acme_http_config hCfg;
   struct mk_acme_response_data mkrspdata;
   mk_acme_config *pacfg;
   mk_acme_certificate *cert_resp;
   acme_directory dir_resource;
   acme_order_response order_resp;
   acme_authorizations_response authorizations_resp;
   acme_challenges_response challenge_resp;
   acme_finalize_response finalize_resp;
   acme_finalize_response finalize_location_resp;
   mk_mbedtls_key_params mtlsc;
}mk_acme_info;

//static function declarations -- to be used internally.
static int mk_get_acme_directory_resource(mk_acme_info *actx);
static int mk_post_acme_neworder_resource(mk_acme_info *actx);
static int mk_post_acme_finalize_resource(mk_acme_info *actx);
static int mk_post_acme_certificate_resource(mk_acme_info *actx, char *res_url);
static int mk_post_acme_location_url_for_certificate_resource(mk_acme_info *actx);
static int mk_post_acme_authorizations_resource(mk_acme_info *actx);
static int mk_acme_check_resource_response_status(char *status);
static int mk_post_acme_challenges_resource(mk_acme_info *actx, char *challenge_url, char *challenge_payload);
static int mk_prepare_acme_resource_msg(mk_acme_info *actx, char *res_url);
static int mk_get_acme_new_nonce(mk_acme_info *actx, char *newNonce);
static int mk_read_filedata(char *filepath , char *buf, int buflen);
static int mk_update_esp_http_config(esp_http_client_config_t *ecfg, mk_acme_http_config *mkcfg);
static int mk_json_get_string_item_value(const cJSON * jsrc, char *name, char **ppout);
static int mk_json_get_array_item_value(const cJSON * jroot, char *name, int index, char **ppout);
static int mk_json_parse_directory_resource(char *databuff, acme_directory *dr);
static int mk_json_free_directory_resource(acme_directory *dr);
static int mk_json_parse_order_response(char *databuff, acme_order_response *or);
static int mk_json_free_order_resp(acme_order_response *or);
static int mk_json_parse_auth_challenge_array(__challenges *pref, cJSON *jiarray, int index);
static int mk_json_parse_challenge(__challenges *pref, cJSON *jdata);
static int mk_json_parse_authorizations_response(char *databuff, acme_authorizations_response *or);
static int mk_json_parse_challenges_response(char *databuff, acme_challenges_response *or);
static int mk_json_free_authorizations_resp(acme_authorizations_response *or);
static int mk_json_free_challenges_resp(acme_challenges_response *or);
static int mk_json_parse_finalize_response(char *databuff, acme_finalize_response *or);
static int mk_json_free_finalize_resp(acme_finalize_response *or);
static int mk_convert_to_base64(char *src, size_t slen, char *dst64, size_t dsz);
static int mk_prepare_signature(mk_acme_info *actx);
static int mk_acme_create_csr_from_key(mk_acme_info *actx);

static int mk_init_mbedtls_key_params(mk_acme_info * actx);
static int mk_free_mbedtls_key_params(mk_acme_info * actx);
static int mk_load_acme_keys(mk_acme_info * actx);

static int __mimik_obtain_acme_certificate(mk_acme_info *actx);
static int __mimik_free_acme_resources(mk_acme_info * actx);


/**
 * @brief mk_esp_http_acme_req_rsp prepares and sends http/https request as 
 *        directed in mk_acme_http_config and returns the recived response message.
 *
 * @param[in]   mkcfg       mk_acme_http_config for the client. [mandatory]
 * @param[out]  mkrsp       pointer to struct mk_acme_response_data to fill rx data
 * @param[in]   mkrsp       pointer to struct mk_acme_response_data where rxdata info is filled.
 * @return                returns the length of received message on success and -1 on error
 */
int mk_esp_http_acme_req_rsp(struct mk_acme_http_config *mkcfg, struct mk_acme_response_data *mkrsp);

/* -------------------------------------------------------------------------- */

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
char g_log_lvl = LOG_INFO;

/* -------------------------------------------------------------------------- */
static mk_acme_info g_acme_ctx;
/* -------------------------------------------------------------------------- */

// The following default files are embedded as binary data in 
// and is available to the component and the file contents will be 
// contents will be added to the .rodata section in flash, and are available via symbol names
// https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html#embedding-binary-data

/*
   When building, need to setup component.mk as follows:
#                                                                             
# "main" pseudo-component makefile.                                           
#                                                                             
# (Uses default behaviour of compiling all source files in directory, adding 'include' to include path.)
                                                                              
# embed files from the "certs" directory as binary data symbols               
# in the app                                                                  
COMPONENT_EMBED_TXTFILES += acct_key.pem

*/

extern const uint8_t acct_key_pem_start[] asm("_binary_acct_key_pem_start");
extern const uint8_t acct_key_pem_end[]   asm("_binary_acct_key_pem_end");

//static function definitions.

esp_err_t mk_acme_http_event_handler(esp_http_client_event_t *evt)
{
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            MK_LOG(LOG_INFO, "%s() HTTP_EVENT_ERROR \n",__func__);
            break;
        case HTTP_EVENT_ON_HEADER:
            // MK_LOG(LOG_DEBUG, "%s() HTTP_EVENT_ON_HEADER, key=%s, value=%s \n", __func__,evt->header_key, evt->header_value);
            if (strcmp(evt->header_key, HEADER_ACME_REPLAY_NONCE) == 0) {
                struct mk_acme_response_data *rd = (struct mk_acme_response_data *)evt->user_data;
                memset(rd->Replay_Nonce,0,NONCE_SZ);
                strncpy(rd->Replay_Nonce,evt->header_value,NONCE_SZ);
                //MK_LOG(LOG_DEBUG, "%s() HTTP_EVENT_ON_HEADER, Replay-Nonce => %s \n", __func__,rd->Replay_Nonce);
            }
            //Looks like rfc says Location: but we receive location:
            //Hence for now do a strcasecmp for "location"
            if (strcasecmp(evt->header_key, HEADER_ACME_LOCATION) == 0) {
                struct mk_acme_response_data *rd = (struct mk_acme_response_data *)evt->user_data;
                memset(rd->location, 0, LOCATION_SZ);
                rd->location_len = 0;
                strncpy(rd->location, evt->header_value, LOCATION_SZ);
                rd->location_len = strlen(rd->location);
                MK_LOG(LOG_INFO, "%s() HTTP_EVENT_ON_HEADER, location => %s \n", __func__,rd->location);
            }
            break;
        case HTTP_EVENT_ON_DATA:
            MK_LOG(LOG_INFO, "%s() HTTP_EVENT_ON_DATA, len=%d \n", __func__,evt->data_len);
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // MK_LOG(LOG_DEBUG,"%s() data_len=%d \n", __func__,evt->data_len);
                if (evt->user_data) {
                    struct mk_acme_response_data *rd = (struct mk_acme_response_data *)evt->user_data;
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

static int mk_read_filedata(char *filepath , char *buf, int buflen)
{
    int rc = 0; 
    int fd = 0; 
    if ((!filepath)||(!buf)||(buflen <= 0)) {
       return -1;
    }

    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
	MK_LOG(LOG_ERR, "%s() open() failed for %s. err=%d(%s) \n", 
			  __func__,filepath,errno,strerror(errno));
	return -1;
    }
    rc = read(fd, buf, buflen);
    if (rc < 0) {
	MK_LOG(LOG_ERR, "%s() read() failed. err=%d(%s) \n", __func__,errno,strerror(errno));
	close(fd);
	return -1;
    }
    close(fd);

    return 0;
}

static int mk_update_esp_http_config(esp_http_client_config_t *ecfg, mk_acme_http_config *mkcfg)
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
   
   ecfg->event_handler = mk_acme_http_event_handler;

   if (mkcfg->http_proto == MK_PROTO_HTTPS) {
        // https using TLS security and SSL
        ecfg->transport_type = HTTP_TRANSPORT_OVER_SSL;
   }
   else {
        // plain http
        ecfg->transport_type = HTTP_TRANSPORT_OVER_TCP;
   }

   if (mkcfg->timeoutsec <= 0) {
       mkcfg->timeoutsec = DFT_HTTPS_TIMEOUT_SEC;
   }

   if (mkcfg->buffer_size <= 0) {
      ecfg->buffer_size = DFT_HTTPS_DFT_BUFFER_SZ ;
   }
   else {
      ecfg->buffer_size = mkcfg->buffer_size;
   }
   ecfg->timeout_ms = mkcfg->timeoutsec * 1000;

   return 0;
}

// GET /acme/v2/directory HTTP/1.1
// Accept: application/json, text/plain
// User-Agent: mimik
// Content-Type: application/jose+json
// Host: localhost:8088
// Connection: close

// returns content_length on success else returns -1 on error 
int mk_esp_http_acme_req_rsp(struct mk_acme_http_config *mkcfg, struct mk_acme_response_data *mkrsp)
{
   int rc = 0;
   int content_length = 0;
   int status_code = 0;
   esp_http_client_config_t espCfg = {0}; 
   esp_http_client_handle_t espclient = NULL;
   esp_err_t err = 0;
   char *hname = NULL;
   char *hval = NULL;

   rc = mk_update_esp_http_config(&espCfg, mkcfg);
   if (rc < 0) {
      MK_LOG(LOG_ERR,"%s() mk_update_esp_http_config failed.\n",__func__);
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

   if ((mkcfg->http_method == MK_HTTP_METHOD_POST) && mkcfg->post_msg && (mkcfg->post_msg_len > 0)) {
      err = esp_http_client_set_post_field(espclient, mkcfg->post_msg, mkcfg->post_msg_len);
      if (err == ESP_OK) {
         err = esp_http_client_set_method(espclient, HTTP_METHOD_POST);
      }
      if (err != ESP_OK) {
         MK_LOG(LOG_ERR, "%s: set_post error %d %s", __func__, err, esp_err_to_name(err));
         esp_http_client_cleanup(espclient);
         return -1;
      } 
   }

   if (mkcfg->http_method == MK_HTTP_METHOD_HEAD) {
      err = esp_http_client_set_method(espclient, HTTP_METHOD_HEAD);
      if (err != ESP_OK) {
         MK_LOG(LOG_ERR, "%s: set_method_head error %d %s", __func__, err, esp_err_to_name(err));
         esp_http_client_cleanup(espclient);
         return -1;
      }
   }

   if (mkcfg->set_Accept) {
      hname = "Accept";
      hval = mkcfg->set_Accept;
      err = esp_http_client_set_header(espclient, hname, hval);
      if (err != ESP_OK) {
         MK_LOG(LOG_ERR, "%s: set_header(%s:%s) error %d %s", __func__, hname,hval,err, esp_err_to_name(err));
      }
   }

   if (mkcfg->set_UserAgent) {
      hname = "User-Agent";
      hval = mkcfg->set_UserAgent;
      err = esp_http_client_set_header(espclient, hname, hval);
      if (err != ESP_OK) {
         MK_LOG(LOG_ERR, "%s: set_header(%s:%s) error %d %s", __func__, hname,hval,err, esp_err_to_name(err));
      }
   }

   if (mkcfg->set_Content_Type) {
      hname = "Content-Type";
      hval = mkcfg->set_Content_Type;
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

int mk_json_get_array_item_value(const cJSON * jroot, char *name, int index, char **ppout)
{
   cJSON *jobject = NULL;
   cJSON *jitem = NULL;

   if ((!jroot) || (!name) || (!ppout) || (index < 0)) {
     return -1;
   }

   jobject = cJSON_GetObjectItemCaseSensitive(jroot, name);
   if (jobject && cJSON_IsArray(jobject)) {
       int asz = cJSON_GetArraySize(jobject);
       if (index > asz) {
          return -1;
       }
       jitem = cJSON_GetArrayItem(jobject, index);
       if (jitem) {
           *ppout = cJSON_GetStringValue(jitem);
           //MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,(*ppout)?(*ppout):"");
           return 0;
       }
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
        // MK_LOG(LOG_DEBUG,"%s() name(%s) => (addr=%p):value(%s) \n ",__func__,name,*ppout,*ppout);
        return 0;
   }
   return -1;
}

int mk_json_free_directory_resource(acme_directory *dr)
{
   if (dr && dr->jroot) {
      cJSON_Delete((cJSON *)dr->jroot);
      dr->jroot = NULL;
      memset(dr,0,sizeof(acme_directory));
   }
   return 0;
}

//mk_json_parse_directory_resource() parses the content of the string databuff as
//JSON object to equivalent c struct and places the result in structure members.
//returns 0 on success and -1 on failure
int mk_json_parse_directory_resource(char *databuff, acme_directory *dr)
{
   cJSON *jroot = NULL;
   char *name = NULL;
   int rc = 0;

   if ((!databuff) || (!dr)) {
      return -1;
   }

   if (dr->jroot != NULL) {
      MK_LOG(LOG_ERR,"%s() dr->jroot=%p is not empty, may have been parsed already \n",__func__,dr->jroot);
      mk_json_free_directory_resource(dr);
   }

   jroot = cJSON_Parse(databuff);
   if (!jroot) {
      return -1;
   }
   dr->jroot = jroot;

   //"newAccount"
    name = "newAccount";
    rc = mk_json_get_string_item_value(jroot,name,&dr->newAccount);
    if (rc == 0) {
        MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,dr->newAccount);
    }

   //"newNonce"
    name = "newNonce";
    rc = mk_json_get_string_item_value(jroot,name,&dr->newNonce);
    if (rc == 0) {
        MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,dr->newNonce);
    }

   //"newOrder"
    name = "newOrder";
    rc = mk_json_get_string_item_value(jroot,name,&dr->newOrder);
    if (rc == 0) {
        MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,dr->newOrder);
    }

   return 0;
}

int mk_json_free_order_resp(acme_order_response *or)
{
   if (or && or->jroot) {
      cJSON_Delete((cJSON *)or->jroot);
      or->jroot = NULL;
      memset(or,0,sizeof(acme_order_response));
   }
   return 0;
}

static int mk_json_parse_order_response(char *databuff, acme_order_response *or)
{
   cJSON *jroot = NULL;
   char *name = NULL;
   int rc = 0;

   if ((!databuff) || (!or)) {
      return -1;
   }

   if (or->jroot != NULL) {
      MK_LOG(LOG_ERR,"%s() or->jroot=%p is not empty, may have been parsed already \n",__func__,or->jroot);
      mk_json_free_order_resp(or);
   }

   jroot = cJSON_Parse(databuff);
   if (!jroot) {
      return -1;
   }
   or->jroot = jroot;

   //"finalize"
    name = "finalize";
    rc = mk_json_get_string_item_value(jroot,name,&or->finalize);
    if (rc == 0) {
        MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,or->finalize);
    }

   //mimik's specific "orderId" exact string not in rf8555 fields
    //"orderId"
    name = "orderId";
    rc = mk_json_get_string_item_value(jroot,name,&or->orderId);
    if (rc == 0) {
        MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,or->orderId);
    }

    //"authorizations"
    name = "authorizations";  //an array of items, choose the first item for now
    rc = mk_json_get_array_item_value(jroot, name, 0, &or->authorizations);
    if (rc == 0) {
        MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,or->authorizations);
    }

    //"status"
    name = "status";
    rc = mk_json_get_string_item_value(jroot,name,&or->status);
    if (rc == 0) {
        MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,or->status);
    }

   return 0;
}

int mk_json_free_authorizations_resp(acme_authorizations_response *or)
{
   if (or && or->jroot) {
      cJSON_Delete((cJSON *)or->jroot);
      or->jroot = NULL;
      memset(or,0,sizeof(acme_authorizations_response));
   }
   return 0;
}

int mk_json_free_challenges_resp(acme_challenges_response *or)
{
   if (or && or->jroot) {
      cJSON_Delete((cJSON *)or->jroot);
      or->jroot = NULL;
      memset(or,0,sizeof(acme_authorizations_response));
   }
   return 0;
}

int mk_json_parse_authorizations_response(char *databuff, acme_authorizations_response *or)
{
   cJSON *jroot = NULL;
   cJSON *jobject= NULL;
   char *name = NULL;
   int rc = 0;

   if ((!databuff) || (!or)) {
      return -1;
   }

   if (or->jroot != NULL) {
      MK_LOG(LOG_ERR,"%s() or->jroot=%p is not empty, may have been parsed already \n",__func__,or->jroot);
      mk_json_free_authorizations_resp(or);
   }

   jroot = cJSON_Parse(databuff);
   if (!jroot) {
      return -1;
   }
   or->jroot = jroot;

   //"status"
   name = "status";
   rc = mk_json_get_string_item_value(jroot,name,&or->status);
   if (rc == 0) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,or->status);
   }

   //"challenges":[array]
   name = "challenges";  //an array of items, choose the first item for now
   jobject = cJSON_GetObjectItemCaseSensitive(jroot, name);
   if (!jobject) {
      return -1;
   }

   //get challenges array object items: url, type, status and token
   rc = mk_json_parse_auth_challenge_array(&or->challenges, jobject, 0);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
      return -1;
   }

   return 0;
}

int mk_json_parse_auth_challenge_array(__challenges *pref, cJSON *jiarray, int index)
{
   cJSON *jdata = NULL;
   int rc = 0;

   if ((!pref)||(!jiarray)||(!cJSON_IsArray(jiarray))) {
      MK_LOG(LOG_ERR,"%s() Invalid param \n ",__func__);
      return -1;
   }

   jdata = cJSON_GetArrayItem(jiarray,index);
   if (!jdata) {
     MK_LOG(LOG_ERR,"%s() Unable to get array object at index=%d \n ",__func__,index);
     return -1;
   }

   rc = mk_json_parse_challenge(pref, jdata);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
      return -1;
   }

   return 0 ;
}

int mk_json_parse_challenge(__challenges *pref, cJSON *jdata)
{
   char **ppout = NULL;
   char *name = NULL;
   int rc = 0;

   if ((!pref)||(!jdata)) {
      MK_LOG(LOG_ERR,"%s() Invalid param \n ",__func__);
      return -1;
   }

   //"url"
   name = "url";
   ppout = &pref->url;
   rc = mk_json_get_string_item_value(jdata,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"type"
   name = "type";
   ppout = &pref->type;
   rc = mk_json_get_string_item_value(jdata,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"status"
   name = "status";
   ppout = &pref->status;
   rc = mk_json_get_string_item_value(jdata,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   //"token"
   name = "token";
   ppout = &pref->token;
   rc = mk_json_get_string_item_value(jdata,name,ppout);
   if ((rc == 0) && (*ppout)) {
       MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,*ppout);
   }

   return 0;
}

int mk_json_parse_challenges_response(char *databuff, acme_challenges_response *or)
{
   cJSON *jroot = NULL;
   int rc = 0;

   if ((!databuff) || (!or)) {
      return -1;
   }

   if (or->jroot != NULL) {
      MK_LOG(LOG_DEBUG,"%s() or->jroot=%p is not empty, may have been parsed already \n",__func__,or->jroot);
      mk_json_free_challenges_resp(or);
   }

   jroot = cJSON_Parse(databuff);
   if (!jroot) {
      return -1;
   }
   or->jroot = jroot;

   //get challenges array object items: url, type, status and token
   rc = mk_json_parse_challenge(&or->challenges, jroot);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
      return -1;
   }

   return 0;
}


int mk_json_free_finalize_resp(acme_finalize_response *or)
{
   if (or && or->jroot) {
      cJSON_Delete((cJSON *)or->jroot);
      or->jroot = NULL;
      memset(or,0,sizeof(acme_finalize_response));
   }
   return 0;
}

int mk_json_parse_finalize_response(char *databuff, acme_finalize_response *or)
{
   cJSON *jroot = NULL;
   char *name = NULL;
   int rc = 0;

   if ((!databuff) || (!or)) {
      return -1;
   }

   if (or->jroot != NULL) {
      MK_LOG(LOG_ERR,"%s() or->jroot=%p is not empty, may have been parsed already \n",__func__,or->jroot);
      mk_json_free_finalize_resp(or);
   }

   jroot = cJSON_Parse(databuff);
   if (!jroot) {
      return -1;
   }
   or->jroot = jroot;

   //"certificate"
    name = "certificate";
    rc = mk_json_get_string_item_value(jroot,name,&or->certificate);
    if (rc == 0) {
        MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,or->certificate);
    }

   //"status"
    name = "status";
    rc = mk_json_get_string_item_value(jroot,name,&or->status);
    if (rc == 0) {
        MK_LOG(LOG_DEBUG,"%s() name(%s) => value(%s) \n ",__func__,name,or->status);
    }

   return 0;
}

static int mk_get_acme_directory_resource(mk_acme_info *actx)
{
    int rc = 0;
    if (!actx) {
       return -1;
    }

   // GET directory object from ACME server
    // ACME client first need to obtain directory object from ACME server to configure
    // themselves with the right URLs (provided in the directory JSON object
    // for each ACME operation. This is the only URL needed to configure clients.
    // newNonce, newAccount, newOrder, newAuthz(New authorization),
    // revokeCert(Revoke certificate),  keyChange (Key change)

    actx->hCfg.http_url = actx->pacfg->acme_directory_url;

    actx->hCfg.http_method = MK_HTTP_METHOD_GET;
    actx->hCfg.set_Content_Type = MK_HTTP_SET_CONTENT_TYPE_JOSE_JSON;
    actx->hCfg.set_Host = MK_HTTP_SET_HOST_LOCALHOST;
    actx->hCfg.set_UserAgent = MK_HTTP_SET_USER_AGENT_MIMIK;
    actx->hCfg.set_Accept = NULL;
    actx->hCfg.post_msg = NULL;

    actx->mkrspdata.rsp_buff = actx->rxbuf;
    actx->mkrspdata.rsp_max_buff_sz = RXBUFSZ;
    memset(actx->rxbuf,0,RXBUFSZ);
    rc = mk_esp_http_acme_req_rsp(&actx->hCfg, &actx->mkrspdata);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->mkrspdata.rsp_buff[actx->mkrspdata.rsp_rx_bytes] = 0; //NULL terminate, just in case, to be used as a string buffer
    MK_LOG(LOG_INFO, "%s(): recvd rc=%d mkrspdata[rsp_rx_bytes=%d content_length=%d] \n",
                      __func__,rc,actx->mkrspdata.rsp_rx_bytes,actx->mkrspdata.content_length);
    //Parse directory resource JSON object and the obtain the values of 
    //newNonce, newAccount, newOrder
    rc = mk_json_parse_directory_resource(actx->mkrspdata.rsp_buff, &actx->dir_resource);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }
    
    return 0;
}

//slen	amount of data to be encoded
//dsz	size of the destination buffer
//returns length of bytes written to dst64 and -1 on error
int mk_convert_to_base64(char *src, size_t slen, char *dst64, size_t dsz)
{
   size_t dstlen = 0 ;
   int i = 0;
   int rc = 0;

   if ((!src)||(slen <= 0)||(!dst64)||(dsz < slen)) {
      return -1;
   }

  /*
   mbedtls_base64_encode() Returns 0 if successful, MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL, or
   MBEDTLS_ERR_BASE64_INVALID_CHARACTER if the input data is not correct. *dstlen is
   always updated to reflect the amount of data that has (or would have) been
   written.
  */

  rc = mbedtls_base64_encode((unsigned char *)dst64, dsz, &dstlen, (unsigned char *)src, slen);
  if (rc != 0) {
     MK_LOG(LOG_ERR,"%s() mbedtls_base64_encode failed: slen=%d dsz=%d dstlen=%d rc=%d \n",
                __func__,slen,dsz,dstlen,rc);
     return -1;
  }

  MK_LOG(LOG_DEBUG ,"%s() mbedtls_base64_encode-1: slen=%d dstlen=%d strlen(dst64)=%d \n",
                __func__,slen,dstlen,strlen(dst64));
  /*
   As per logic given in Appendix C of RFC 7515  JSON Web Signature (JWS)
   To implement base64url encoding and decoding functions without padding based upon
   standard base64 encoding and decoding functions that do use padding.  

   The rule to change base64 without padding is:
   // Remove any trailing '=' and change it to 0
   // s.Replace('+', '-');
   // s.Replace('/', '_');

  */
  
  for (i = 0; i <= dstlen; i++) {
     switch(dst64[i]) {
	case '+':
	 dst64[i] = '-';
	 break;
	case '/':
	 dst64[i] = '_';
	 break;
	case  '=':
        {
	 dst64[i] = 0;
         //MK_LOG(LOG_DEBUG ,"%s(_CHANGE) mbedtls_base64_encode= slen=%d dstlen=%d strlen(dst64)=%d \n",
         //       __func__,slen,dstlen,strlen(dst64));
        }
	 break;
	default:
	 break;
     }
  }

  MK_LOG(LOG_DEBUG ,"%s() mbedtls_base64_encode-2 success: slen=%d dstlen=%d strlen(dst64)=%d \n",
                __func__,slen,dstlen,strlen(dst64));
    
  return dstlen;
}

static int mk_prepare_signature(mk_acme_info *actx)
{
    int ret = 0;
    int b64len = 0;
    size_t signature_len = 0;

    // Needed for computing the signature of protected and payload members
    #define MD_HASH_SZ 32
    char mdhash[MD_HASH_SZ] = {0};
    mbedtls_md_info_t *mddigest = NULL;

    if (!actx) {
       return -1;
    }

   /*
	 rfc8555: 'Communications between an ACME client and an ACME server are
done  over HTTPS, using JSON Web Signature (JWS) [RFC7515] to provide
some additional security properties for messages sent from the client to
the server.'

	rfc8555: 'The "signature" field of the JWS will contain the Message
Authentication Code (MAC), value computed with the MAC key provided by the
certification authorities (CAs).'

    */
   
    // get message-digest information associated with the given digest type : MBEDTLS_MD_SHA256
    mddigest = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!mddigest) {
        MK_LOG(LOG_ERR,"%s() mbedtls_md_info_from_type failed \n",__func__);
        return -1;
    }

    /*                                                                        
     * call message digest --- md -- function mbedtls_md() and compute the SHA-256 hash of the
     * data in tx_msg.temp_msg_buf buffer
     */

    memset(actx->tx_msg.temp_msg_buf,0,MAX_TMP_BUF_SZ);

    //Copy "protected64.payload64" values as a string into temp_msg_buf for
    //computing its SHA-256 message digest value, needed later to obtian the "signature"

    snprintf(actx->tx_msg.temp_msg_buf, MAX_TMP_BUF_SZ, "%s.%s",
                  actx->tx_msg.protected_base64_str, actx->tx_msg.payload_base64_str);

    MK_LOG(LOG_DEBUG,"%s() calling mbedtls_md(), strlen(temp_msg_buf=%d) => %s\n",
                                 __func__,strlen(actx->tx_msg.temp_msg_buf),actx->tx_msg.temp_msg_buf);

    ret = mbedtls_md(mddigest, (const unsigned char *)actx->tx_msg.temp_msg_buf, 
	       strlen(actx->tx_msg.temp_msg_buf), (unsigned char *)mdhash);
    if (ret != 0) {
       MK_LOG(LOG_ERR,"%s() mbedtls_md failed, error ret=0x%x \n",__func__, -ret);
       return -1;
    }

/**
From: /mbedtls/pk.h
 * \brief           Make signature, including padding if relevant.
 *
 * \param ctx       The PK context to use. It must have been set up
 *                  with a private key.
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Place to write the signature
 * \param sig_len   Number of bytes written
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 on success, or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  There is no interface in the PK module to make RSASSA-PSS
 *                  signatures yet.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            For RSA, md_alg may be MBEDTLS_MD_NONE if hash_len != 0.
 *                  For ECDSA, md_alg may never be MBEDTLS_MD_NONE.
 */
/*
int mbedtls_pk_sign( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
*/
    MK_LOG(LOG_DEBUG,"%s() calling mbedtls_pk_sign() , mbedtls_pk_get_len(&actx->mtlsc.acct_pkey)=%d time-start=%ld sec\n",
                                   __func__,mbedtls_pk_get_len(&actx->mtlsc.acct_pkey),time(NULL));

    memset(actx->tx_msg.temp_msg_buf,0,MAX_TMP_BUF_SZ); //reuse the temp_msg_buf for getting the signature
    ret = mbedtls_pk_sign(&actx->mtlsc.acct_pkey, MBEDTLS_MD_SHA256, (const unsigned char *)mdhash, MD_HASH_SZ,
               (unsigned char *)actx->tx_msg.temp_msg_buf, &signature_len, mbedtls_ctr_drbg_random, &actx->mtlsc.ctr_drbg_ctx);
    if (ret != 0) {
       MK_LOG(LOG_ERR,"%s() mbedtls_pk_sign failed, error ret=(-0x%04x) \n",__func__, -ret);
       return -1;
    }

    // This also works: passing NULL for random function f_rng and NULL for seed p_rng instead of above mbedtls_ctr_drbg_random
    //ret = mbedtls_pk_sign(&actx->mtlsc.acct_pkey, MBEDTLS_MD_SHA256, (const unsigned char *)mdhash, MD_HASH_SZ,
    //           (unsigned char *)actx->tx_msg.temp_msg_buf, &signature_len, NULL,  NULL);

    // NOTE: We could also use mbedtls_rsa_pkcs1_sign( ) for creating signature, and explicty set it to use MBEDTLS_RSA_PRIVATE key.

    MK_LOG(LOG_DEBUG,"%s() mbedtls_pk_sign() success, with  signature_len=%d time-end=%ld sec \n", __func__,signature_len,time(NULL));

    memset(actx->tx_msg.signature_base64,0,MAX_SIGNATURE_SZ);
    //NOTE: actx->tx_msg.temp_msg_buf now contains the signature message obtained from above mbedtls_pk_sign() call
    //   signature_len is the length of the signature in bytes stored now temporarily in actx->tx_msg.temp_msg_buf
    b64len = mk_convert_to_base64(actx->tx_msg.temp_msg_buf, signature_len, actx->tx_msg.signature_base64, MAX_SIGNATURE_SZ);
    if (b64len < 0) {
      MK_LOG(LOG_ERR, "%s(): Error mk_convert_to_base64 for signature\n",__func__);
       return -1;
    }

    MK_LOG(LOG_DEBUG,"%s(_SIG) signature success strlen(actx->tx_msg.signature_base64)=%d b64len=%d \n",
                                 __func__,strlen(actx->tx_msg.signature_base64),b64len);

    return 0;
}

static int mk_prepare_acme_resource_msg(mk_acme_info *actx, char *res_url)
{
    int rc = 0;
    int slen = 0;

    if ((!actx) || (!res_url)) {
       return -1;
    }

    //"protected" section
    slen = strlen(actx->tx_msg.protected_str);
    if (slen > 0) {
       rc = mk_convert_to_base64(actx->tx_msg.protected_str, slen, actx->tx_msg.protected_base64_str, MAX_PROTECTED_SZ);
       if ( rc < 0) {
	 MK_LOG(LOG_ERR, "%s(): Error mk_convert_to_base64 for protected_str=%s\n",__func__,actx->tx_msg.protected_str);
	  return -1;
       }
    }

    //"payload": section
    slen = strlen(actx->tx_msg.payload_str);
    if (slen > 0) {
       rc = mk_convert_to_base64(actx->tx_msg.payload_str, slen, actx->tx_msg.payload_base64_str, MAX_PAYLOAD_SZ);
       if ( rc < 0) {
	 MK_LOG(LOG_ERR, "%s(): Error mk_convert_to_base64 for payload_str=%s\n",__func__,actx->tx_msg.payload_str);
	  return -1;
       }
    }

    //"signature": section
    mk_prepare_signature(actx);


    // Now copy the final message (everything) to txbuf for sending it to the server
    snprintf(actx->tx_msg.txbuf, MAX_TX_BUF_SZ, ACME_RESOURCE_MSG_JSON_SPRINTF_FORMAT, 
                  actx->tx_msg.protected_base64_str, actx->tx_msg.payload_base64_str, actx->tx_msg.signature_base64);

    actx->tx_msg.txlen = strlen(actx->tx_msg.txbuf);

    MK_LOG(LOG_INFO, "%s(TX_MSG): res_url=%s msg json object[txlen=%d] \n\n",
                              __func__,res_url,actx->tx_msg.txlen);

    return 0;
}

//POST newOrder
static int mk_post_acme_neworder_resource(mk_acme_info *actx)
{
    int rc = 0;
    char *res_url = NULL;

    if ((!actx) || (!actx->dir_resource.newOrder)) {
       return -1;
    }

    actx->hCfg.http_url = actx->dir_resource.newOrder ;

    actx->hCfg.http_method = MK_HTTP_METHOD_POST;
    actx->hCfg.set_Content_Type = MK_HTTP_SET_CONTENT_TYPE_JOSE_JSON;
    actx->hCfg.set_Host = MK_HTTP_SET_HOST_LOCALHOST;
    actx->hCfg.set_UserAgent = MK_HTTP_SET_USER_AGENT_MIMIK;
    actx->hCfg.set_Accept = NULL;

    res_url = actx->dir_resource.newOrder;

    //"protected" section
    snprintf(actx->tx_msg.protected_str, MAX_PROTECTED_SZ, ACME_PROTECTED_SPRINTF_FORMAT, 
               res_url, actx->mkrspdata.Replay_Nonce, actx->kid_KeyId);

    //"payload": identifier preparation section
    memset(actx->tx_msg.identifierb64_value_dot_device, 0, MAX_IDENTIFIER_BUF_SZ);
    memset(actx->tx_msg.identifierb64_value, 0, MAX_IDENTIFIER_BUF_SZ);
    memset(actx->tx_msg.identifier_value, 0, MAX_IDENTIFIER_BUF_SZ);

    snprintf(actx->tx_msg.identifier_value, MAX_IDENTIFIER_BUF_SZ, ACME_MIMIK_DEVICE_IDENTIFIER_SPRINTF_FORMAT,
                                            actx->pacfg->device_id, actx->pacfg->client_id, actx->pacfg->scope);

    rc = mk_convert_to_base64(actx->tx_msg.identifier_value, strlen(actx->tx_msg.identifier_value),
                                             actx->tx_msg.identifierb64_value, MAX_IDENTIFIER_BUF_SZ);
    if ( rc < 0) {
        MK_LOG(LOG_ERR, "%s(): Error mk_convert_to_base64 for identifier_value=%s\n",__func__,actx->tx_msg.identifier_value);
	return -1;
    }

    snprintf(actx->tx_msg.identifierb64_value_dot_device , MAX_IDENTIFIER_BUF_SZ, "%s.device", actx->tx_msg.identifierb64_value);

    //"payload": section
    snprintf(actx->tx_msg.payload_str, MAX_PAYLOAD_SZ, ACME_PAYLOAD_MIMIK_ORDER_SPRINTF_FORMAT, actx->tx_msg.identifierb64_value_dot_device);

    rc = mk_prepare_acme_resource_msg(actx, actx->dir_resource.newOrder);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): mk_prepare_acme_resource_msg Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->hCfg.post_msg = actx->tx_msg.txbuf;
    actx->hCfg.post_msg_len = actx->tx_msg.txlen;

    actx->mkrspdata.rsp_buff = actx->rxbuf;
    actx->mkrspdata.rsp_max_buff_sz = RXBUFSZ;
    memset(actx->rxbuf,0,RXBUFSZ);
    rc = mk_esp_http_acme_req_rsp(&actx->hCfg, &actx->mkrspdata);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->mkrspdata.rsp_buff[actx->mkrspdata.rsp_rx_bytes] = 0; //NULL terminate, just in case, to be used as a string buffer
    MK_LOG(LOG_DEBUG, "%s(): recvd rc=%d mkrspdata[rsp_rx_bytes=%d content_length=%d] \n",
                      __func__,rc,actx->mkrspdata.rsp_rx_bytes, actx->mkrspdata.content_length);

    //Parse directory resource JSON object and the obtain the values of finalize resource url
    rc = mk_json_parse_order_response(actx->mkrspdata.rsp_buff, &actx->order_resp);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }
    
    return 0;
}

int mk_acme_check_resource_response_status(char *status)
{
   if (!status) {
     MK_LOG(LOG_ERR, "%s(): status is empty \n",__func__);
     return -1;
   }

  //NOTE rfc8555 7.1.3.  Order Objects status: "ready" and "processing" are possible.
  //NOTE rfc8555 7.1.6. Status Changes: 'Challenge objects are created in the "pending" state.
  //They transition to the "processing" state when the client responds to the  challenge'

   //if ((strcasecmp(status, "valid") == 0) ||
        //(strcasecmp(status, "ready") == 0) ||
        //(strcasecmp(status, "processing") == 0) ||
       // (strcasecmp(status, "pending") == 0)) {
     // return 0;
   //}

   if ((strcasecmp(status, "valid") == 0) ||
        (strcasecmp(status, "pending") == 0)) {
      return 0;
   }

   MK_LOG(LOG_ERR, "%s(): status = %s \n",__func__,status);
   return -1;
}

int mk_acme_create_csr_from_key(mk_acme_info *actx)
{
  //NOTE: For ACME, as per rfc8555, "finalize" request -- "payload" -- should
  //include Certificate Signing Request (CSR) data generated from client key in
  //Distinguished Encoding Rules(DER) format.

  int ret = 0;
  mk_mbedtls_key_params *pmtls = NULL;
  mbedtls_x509write_csr	csrcfg;
  
  pmtls = &actx->mtlsc;

  memset(&csrcfg, 0, sizeof(csrcfg));

  mbedtls_x509write_csr_init(&csrcfg);

  mbedtls_x509write_csr_set_md_alg(&csrcfg, MBEDTLS_MD_SHA256);

  // Set the key for a CSR (public key will be included), private key used to sign the CSR when writing it
  //cert_pkey is the generated key pair and contains both private and public key.
  // mbedtls_x509write_csr_set_key includes the public key in CSR and signs the CSR with private key from the key pair.
  mbedtls_x509write_csr_set_key(&csrcfg, &pmtls->cert_pkey);

/*
   rfc8555: csr (required, string):  A CSR encoding the parameters for the
      certificate being requested [RFC2986].  The CSR is sent in the
      base64url-encoded version of the DER format.  (Note: Because this
      field uses base64url, and does not include headers, it is
      different from PEM.)
*/

  //set common name(CN)
/*
   Rules to set CN set in CSR as per RFC 8555:
   The CSR encodes the client's requests with regard to the content of
   the certificate to be issued.  The CSR MUST indicate the exact same
   set of requested identifiers as the initial newOrder request.
   Identifiers of type "dns" MUST appear either in the commonName
   portion of the requested subject name or in an extensionRequest
   attribute [RFC2985] requesting a subjectAltName extension, or both.
   (These identifiers may appear in any sort order.)  Specifications
   that define new identifier types must specify where in the
   certificate signing request these identifiers can appear.
*/

  snprintf(pmtls->csr_cn_name, sizeof(pmtls->csr_cn_name), "CN=%s", actx->tx_msg.identifierb64_value_dot_device);
  ret = mbedtls_x509write_csr_set_subject_name(&csrcfg, pmtls->csr_cn_name);
  if (ret != 0) {
    MK_LOG(LOG_ERR,"%s: mbedtls_x509write_csr_set_subject_name failed ret=0x%x", __func__, -ret);
    mbedtls_x509write_csr_free(&csrcfg);
    return -1;
  }
  // MK_LOG(LOG_DEBUG,"%s(): set csr_cn_name=%s \n", __func__, pmtls->csr_cn_name);

  memset(pmtls->csrbuf, 0, CSR_DATA_SZ);
  pmtls->csr_len = 0;
  pmtls->pcsr = NULL;

  ret = mbedtls_x509write_csr_der(&csrcfg, pmtls->csrbuf, CSR_DATA_SZ, 
                                       mbedtls_ctr_drbg_random, &actx->mtlsc.ctr_drbg_ctx);
  if (ret < 0) {
    MK_LOG(LOG_ERR,"%s: mbedtls_x509write_csr_der failed ret=0x%x", __func__,-ret);
    mbedtls_x509write_csr_free(&csrcfg);
    return -1;
  }

  /* 
    mbedtls_x509write_csr_der() function writes a CSR (Certificate Signing Request) to a DER structure 
    Note: data is written at the end of the buf! Use the return value to determine where you
    should start using the buf. 
  */

  pmtls->csr_len = ret;
  pmtls->pcsr = pmtls->csrbuf + CSR_DATA_SZ - ret;

  mbedtls_x509write_csr_free(&csrcfg);

  return 0;
}

//POST finalize
/* comments from rfc8555:

   "Once the client believes it has fulfilled the server's requirements,
   it should send a POST request to the order resource's finalize URL.
   The POST body MUST include a CSR:

   csr (required, string):  A CSR encoding the parameters for the
      certificate being requested [RFC2986].  The CSR is sent in the
      base64url-encoded version of the DER format.  (Note: Because this
      field uses base64url, and does not include headers, it is
      different from PEM.)

   POST /acme/order/TOlocE8rfgo/finalize HTTP/1.1
   Host: example.com
   Content-Type: application/jose+json

   {
     "protected": base64url({
       "alg": "ES256",
       "kid": "https://example.com/acme/acct/evOfKhNU60wg",
       "nonce": "MSF2j2nawWHPxxkE3ZJtKQ",
       "url": "https://example.com/acme/order/TOlocE8rfgo/finalize"
     }),
     "payload": base64url({
       "csr": "MIIBPTCBxAIBADBFMQ...FS6aKdZeGsysoCo4H9P",
     }),
     "signature": "uOrUfIIk5RyQ...nw62Ay1cl6AB"
   }

   The CSR encodes the client's requests with regard to the content of
   the certificate to be issued.  The CSR MUST indicate the exact same
   set of requested identifiers as the initial newOrder request.
   Identifiers of type "dns" MUST appear either in the commonName
   portion of the requested subject name or in an extensionRequest
   attribute [RFC2985] requesting a subjectAltName extension, or both.
   (These identifiers may appear in any sort order.)  Specifications
   that define new identifier types must specify where in the
   certificate signing request these identifiers can appear."
*/
int mk_post_acme_finalize_resource(mk_acme_info *actx)
{
    int rc = 0;
    char *res_url = NULL;
    mk_mbedtls_key_params *pmtls = NULL;

    if ((!actx) || (!actx->order_resp.finalize)) {
       return -1;
    }

    rc = mk_acme_create_csr_from_key(actx);
    if (rc < 0) {
       MK_LOG(LOG_ERR, "%s(): mk_acme_create_csr_from_key Error rc=%d \n",__func__,rc);
       return -1;
    }

    pmtls = &actx->mtlsc;
    if ((!pmtls->pcsr) || (!pmtls->csr_len)) {
       MK_LOG(LOG_ERR, "%s(): mk_acme_create_csr_from_key Error rc=%d \n",__func__,rc);
       return -1;
    }

    res_url = actx->order_resp.finalize;
    actx->hCfg.http_url = res_url;

    actx->hCfg.http_method = MK_HTTP_METHOD_POST;
    actx->hCfg.set_Content_Type = MK_HTTP_SET_CONTENT_TYPE_JOSE_JSON;
    actx->hCfg.set_Host = MK_HTTP_SET_HOST_LOCALHOST;
    actx->hCfg.set_UserAgent = MK_HTTP_SET_USER_AGENT_MIMIK;
    actx->hCfg.set_Accept = NULL;

    //"protected" section
    snprintf(actx->tx_msg.protected_str, MAX_PROTECTED_SZ, ACME_PROTECTED_SPRINTF_FORMAT, 
               res_url, actx->mkrspdata.Replay_Nonce, actx->kid_KeyId);

    //"payload": section
    //convert CSR into base64(CSR)
    memset(pmtls->csr_base64,0,CSR_DATA_SZ);
    rc = mk_convert_to_base64((char *)pmtls->pcsr, pmtls->csr_len, (char *)pmtls->csr_base64, CSR_DATA_SZ);
    if ( rc < 0) {
      MK_LOG(LOG_ERR, "%s(): Error mk_convert_to_base64 for csr\n",__func__);
       return -1;
    }
    MK_LOG(LOG_DEBUG,"%s() converted csr to csr_base64 strlen(csr_base64)=%d rc=%d \n",
                       __func__,strlen((char *)pmtls->csr_base64),rc);

    snprintf(actx->tx_msg.payload_str, MAX_PAYLOAD_SZ, ACME_PAYLOAD_FINALIZE_CSR_SPRINTF_FORMAT , pmtls->csr_base64);

    rc = mk_prepare_acme_resource_msg(actx, res_url);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): mk_prepare_acme_resource_msg Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->hCfg.post_msg = actx->tx_msg.txbuf;
    actx->hCfg.post_msg_len = actx->tx_msg.txlen;

    actx->mkrspdata.rsp_buff = actx->rxbuf;
    actx->mkrspdata.rsp_max_buff_sz = RXBUFSZ;
    memset(actx->rxbuf,0,RXBUFSZ);
    rc = mk_esp_http_acme_req_rsp(&actx->hCfg, &actx->mkrspdata);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->mkrspdata.rsp_buff[actx->mkrspdata.rsp_rx_bytes] = 0; //NULL terminate, just in case, to be used as a string buffer
    MK_LOG(LOG_INFO, "%s(): recvd rc=%d mkrspdata[rsp_rx_bytes=%d content_length=%d] \n",
                      __func__, rc, actx->mkrspdata.rsp_rx_bytes, actx->mkrspdata.content_length);

    //Parse directory resource JSON object and the obtain the values of certificate resource url
    rc = mk_json_parse_finalize_response(actx->mkrspdata.rsp_buff, &actx->finalize_resp);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }
    
    return 0;
}

//POST-GET certificate 
int mk_post_acme_certificate_resource(mk_acme_info *actx, char *res_url)
{
    int rc = 0;

    if ((!actx) || (!res_url)) {
       return -1;
    }

    actx->hCfg.http_url = res_url;

    actx->hCfg.http_method = MK_HTTP_METHOD_POST;
    actx->hCfg.set_Content_Type = MK_HTTP_SET_CONTENT_TYPE_JOSE_JSON;
    actx->hCfg.set_Host = MK_HTTP_SET_HOST_LOCALHOST;
    actx->hCfg.set_UserAgent = MK_HTTP_SET_USER_AGENT_MIMIK;
    actx->hCfg.set_Accept = MK_HTTP_SET_ACCEPT_PEM_CHAIN;

    //"protected" section
    snprintf(actx->tx_msg.protected_str, MAX_PROTECTED_SZ, ACME_PROTECTED_SPRINTF_FORMAT, 
               res_url, actx->mkrspdata.Replay_Nonce, actx->kid_KeyId);

    //"payload": section carries an empty string when making certifiate resource post-get
    snprintf(actx->tx_msg.payload_str, MAX_PAYLOAD_SZ, "%s" , "");

    rc = mk_prepare_acme_resource_msg(actx, res_url);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): mk_prepare_acme_resource_msg Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->hCfg.post_msg = actx->tx_msg.txbuf;
    actx->hCfg.post_msg_len = actx->tx_msg.txlen;

    actx->mkrspdata.rsp_buff = actx->rxbuf;
    actx->mkrspdata.rsp_max_buff_sz = RXBUFSZ;
    memset(actx->rxbuf,0,RXBUFSZ);
    rc = mk_esp_http_acme_req_rsp(&actx->hCfg, &actx->mkrspdata);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->mkrspdata.rsp_buff[actx->mkrspdata.rsp_rx_bytes] = 0; //NULL terminate, just in case, to be used as a string buffer

    MK_LOG(LOG_INFO, "\n\n%s(): recvd rc=%d mkrspdata[rsp_rx_bytes=%d content_length=%d strlen(rsp_buff)=%d] \n",
                      __func__,rc,actx->mkrspdata.rsp_rx_bytes, actx->mkrspdata.content_length, strlen(actx->mkrspdata.rsp_buff));

    if (actx->cert_resp) {

       // "Certificate:"
       // copy the certificate data into callee's resp certificate buffer
       memset(actx->cert_resp->certificate_pem, 0, MAX_CERTIFICATE_SZ);
       actx->cert_resp->cert_pem_len = actx->mkrspdata.content_length;
       strncpy(actx->cert_resp->certificate_pem, actx->mkrspdata.rsp_buff, MAX_CERTIFICATE_SZ);
       MK_LOG(LOG_INFO, "%s() wrote certificate of len=%d in pem format to user buffer, cert_pem_len=%d \n",
                  __func__,strlen(actx->cert_resp->certificate_pem),actx->cert_resp->cert_pem_len);


       // "CSR:"
       // copy the certificate data into callee's resp csr buffer in DER format
       //DER (Distinguished Encoding Rules) binary encoded format

       // if (actx->mtlsc.pcsr && (actx->mtlsc.csr_len > 0) && (actx->mtlsc.csr_len <= MAX_CERTIFICATE_SZ)) {
       //    memset(actx->cert_resp->csr_der, 0, MAX_CERTIFICATE_SZ);
       //   actx->cert_resp->csr_der_len = actx->mtlsc.csr_len;
       //   memcpy(actx->cert_resp->csr_der, actx->mtlsc.pcsr, actx->mtlsc.csr_len);
       //  }

       // "Private key:"
       // copy the cery_key to callee's resp pri_key_pem buffer in pem format
       memset(actx->cert_resp->pri_key_pem, 0, MAX_CERTIFICATE_SZ);
       rc = mbedtls_pk_write_key_pem(&actx->mtlsc.cert_pkey, (unsigned char *)actx->cert_resp->pri_key_pem, MAX_CERTIFICATE_SZ );
       if (rc == 0) {
           actx->cert_resp->pri_key_pem_len = strlen(actx->cert_resp->pri_key_pem);
           MK_LOG(LOG_INFO, "%s() wrote key of len=%d in pem format to user buffer \n",
                                  __func__,actx->cert_resp->pri_key_pem_len);
       }
    }
    
    return 0;
}

int mk_post_acme_location_url_for_certificate_resource(mk_acme_info *actx)
{
    int rc = 0;
    char * res_url = NULL;

    if ((!actx) || (actx->mkrspdata.location_len == 0)) {
       return -1;
    }

    res_url = actx->mkrspdata.location;
    actx->hCfg.http_url = res_url;

    actx->hCfg.http_method = MK_HTTP_METHOD_POST;
    actx->hCfg.set_Content_Type = MK_HTTP_SET_CONTENT_TYPE_JOSE_JSON;
    actx->hCfg.set_Host = MK_HTTP_SET_HOST_LOCALHOST;
    actx->hCfg.set_UserAgent = MK_HTTP_SET_USER_AGENT_MIMIK;
    actx->hCfg.set_Accept = NULL;

    //"protected" section
    snprintf(actx->tx_msg.protected_str, MAX_PROTECTED_SZ, ACME_PROTECTED_SPRINTF_FORMAT, 
               res_url, actx->mkrspdata.Replay_Nonce, actx->kid_KeyId);

    //"payload": section carries an empty string when making location_url post for certifiate resource readiness
    snprintf(actx->tx_msg.payload_str, MAX_PAYLOAD_SZ, "%s" , "");

    rc = mk_prepare_acme_resource_msg(actx, res_url);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): mk_prepare_acme_resource_msg Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->hCfg.post_msg = actx->tx_msg.txbuf;
    actx->hCfg.post_msg_len = actx->tx_msg.txlen;

    actx->mkrspdata.rsp_buff = actx->rxbuf;
    actx->mkrspdata.rsp_max_buff_sz = RXBUFSZ;
    memset(actx->rxbuf,0,RXBUFSZ);
    rc = mk_esp_http_acme_req_rsp(&actx->hCfg, &actx->mkrspdata);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->mkrspdata.rsp_buff[actx->mkrspdata.rsp_rx_bytes] = 0; //NULL terminate, just in case, to be used as a string buffer

    MK_LOG(LOG_INFO, "\n\n%s(): recvd rc=%d mkrspdata[rsp_rx_bytes=%d content_length=%d strlen(rsp_buff)=%d] \n",
                      __func__,rc,actx->mkrspdata.rsp_rx_bytes, actx->mkrspdata.content_length, strlen(actx->mkrspdata.rsp_buff));

    //Parse directory resource JSON object and the obtain the values of certificate resource url
    rc = mk_json_parse_finalize_response(actx->mkrspdata.rsp_buff, &actx->finalize_location_resp);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }
    
    return 0;
}

int mk_post_acme_authorizations_resource(mk_acme_info *actx)
{
    int rc = 0;
    char * res_url = NULL;

    if ((!actx) || (!actx->order_resp.authorizations)) {
       return -1;
    }

    res_url = actx->order_resp.authorizations;
    actx->hCfg.http_url = res_url;

    actx->hCfg.http_method = MK_HTTP_METHOD_POST;
    actx->hCfg.set_Content_Type = MK_HTTP_SET_CONTENT_TYPE_JOSE_JSON;
    actx->hCfg.set_Host = MK_HTTP_SET_HOST_LOCALHOST;
    actx->hCfg.set_UserAgent = MK_HTTP_SET_USER_AGENT_MIMIK;
    actx->hCfg.set_Accept = NULL;

    //"protected" section
    snprintf(actx->tx_msg.protected_str, MAX_PROTECTED_SZ, ACME_PROTECTED_SPRINTF_FORMAT,
               res_url, actx->mkrspdata.Replay_Nonce, actx->kid_KeyId);

    //"payload": section carries an empty string when making authorizations post
    snprintf(actx->tx_msg.payload_str, MAX_PAYLOAD_SZ, "%s" , "");

    rc = mk_prepare_acme_resource_msg(actx, res_url);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): mk_prepare_acme_resource_msg Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->hCfg.post_msg = actx->tx_msg.txbuf;
    actx->hCfg.post_msg_len = actx->tx_msg.txlen;

    actx->mkrspdata.rsp_buff = actx->rxbuf;
    actx->mkrspdata.rsp_max_buff_sz = RXBUFSZ;
    memset(actx->rxbuf,0,RXBUFSZ);
    rc = mk_esp_http_acme_req_rsp(&actx->hCfg, &actx->mkrspdata);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->mkrspdata.rsp_buff[actx->mkrspdata.rsp_rx_bytes] = 0; //NULL terminate, just in case, to be used as a string buffer

    MK_LOG(LOG_INFO, "\n\n%s(): recvd rc=%d mkrspdata[rsp_rx_bytes=%d content_length=%d strlen(rsp_buff)=%d] \n",
                      __func__,rc,actx->mkrspdata.rsp_rx_bytes, actx->mkrspdata.content_length, strlen(actx->mkrspdata.rsp_buff));

    //Parse directory resource JSON object and the obtain the values of certificate resource url
    rc = mk_json_parse_authorizations_response(actx->mkrspdata.rsp_buff, &actx->authorizations_resp);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

   // /challenges/{Id}?keyAuthorization=<token>.base64(b64data.device)
   memset(actx->tx_msg.mk_challenge_url, 0, MAX_CHALLENGE_URI_LEN);
   if (actx->authorizations_resp.challenges.url) {
       char *token = actx->authorizations_resp.challenges.token ;

       //using temp_msg_buf to get base64(identifierb64_value_dot_device) value needed for keyAuthorization
       memset(actx->tx_msg.temp_msg_buf,0,MAX_TMP_BUF_SZ);
       rc = mk_convert_to_base64(actx->tx_msg.identifierb64_value_dot_device, strlen(actx->tx_msg.identifierb64_value_dot_device),
						actx->tx_msg.temp_msg_buf, MAX_TMP_BUF_SZ);
       if ( rc < 0) {
	   MK_LOG(LOG_ERR, "%s(): Error mk_convert_to_base64 for identifier_value=%s\n",
				   __func__,actx->tx_msg.identifierb64_value_dot_device);
	   return -1;
       }
       snprintf(actx->tx_msg.mk_challenge_url, MAX_CHALLENGE_URI_LEN, "%s?keyAuthorization=%s.%s",
                 actx->authorizations_resp.challenges.url, token?token:"", actx->tx_msg.temp_msg_buf);
   }

   return 0;
}

int mk_post_acme_challenges_resource(mk_acme_info *actx, char *challenge_url, char *challenge_payload)
{
    int rc = 0;
    char * res_url = NULL;

    if ((!actx) || (!challenge_url)) {
       return -1;
    }

    if (!challenge_payload) {
       challenge_payload = "{}"; //for now post an empty object message if NULL
    }

    res_url = challenge_url;
    actx->hCfg.http_url = res_url;

    actx->hCfg.http_method = MK_HTTP_METHOD_POST;
    actx->hCfg.set_Content_Type = MK_HTTP_SET_CONTENT_TYPE_JOSE_JSON;
    actx->hCfg.set_Host = MK_HTTP_SET_HOST_LOCALHOST;
    actx->hCfg.set_UserAgent = MK_HTTP_SET_USER_AGENT_MIMIK;
    actx->hCfg.set_Accept = NULL;

    //"protected" section
    snprintf(actx->tx_msg.protected_str, MAX_PROTECTED_SZ, ACME_PROTECTED_SPRINTF_FORMAT,
               res_url, actx->mkrspdata.Replay_Nonce, actx->kid_KeyId);

    //"payload": section carries an empty string when making authorizations post
    snprintf(actx->tx_msg.payload_str, MAX_PAYLOAD_SZ, "%s" , challenge_payload);

    rc = mk_prepare_acme_resource_msg(actx, res_url);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): mk_prepare_acme_resource_msg Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->hCfg.post_msg = actx->tx_msg.txbuf;
    actx->hCfg.post_msg_len = actx->tx_msg.txlen;

    actx->mkrspdata.rsp_buff = actx->rxbuf;
    actx->mkrspdata.rsp_max_buff_sz = RXBUFSZ;
    memset(actx->rxbuf,0,RXBUFSZ);
    rc = mk_esp_http_acme_req_rsp(&actx->hCfg, &actx->mkrspdata);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    actx->mkrspdata.rsp_buff[actx->mkrspdata.rsp_rx_bytes] = 0; //NULL terminate, just in case, to be used as a string buffer

    MK_LOG(LOG_INFO, "\n\n%s(): recvd rc=%d mkrspdata[rsp_rx_bytes=%d content_length=%d strlen(rsp_buff)=%d] \n",
                      __func__,rc,actx->mkrspdata.rsp_rx_bytes, actx->mkrspdata.content_length, strlen(actx->mkrspdata.rsp_buff));

    //Parse directory resource JSON object and the obtain the values of certificate resource url
    rc = mk_json_parse_challenges_response(actx->mkrspdata.rsp_buff, &actx->challenge_resp);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    return 0;
}

int mk_get_acme_new_nonce(mk_acme_info *actx, char *newNonce)
{
    int rc = 0;
    if ((!actx) || (!newNonce)) {
      MK_LOG(LOG_ERR, "%s(): Error null actx - newNonce param value \n",__func__);
      return -1;
    }

    actx->hCfg.http_url = newNonce;

    actx->hCfg.http_method = MK_HTTP_METHOD_HEAD;
    actx->hCfg.set_Content_Type = MK_HTTP_SET_CONTENT_TYPE_JOSE_JSON;
    actx->hCfg.set_Host = MK_HTTP_SET_HOST_LOCALHOST;
    actx->hCfg.set_UserAgent = MK_HTTP_SET_USER_AGENT_MIMIK;
    actx->hCfg.set_Accept = NULL;
    actx->hCfg.post_msg = NULL;

    actx->mkrspdata.rsp_buff = actx->rxbuf;
    actx->mkrspdata.rsp_max_buff_sz = RXBUFSZ;
    memset(actx->rxbuf,0,RXBUFSZ);
    memset(actx->mkrspdata.Replay_Nonce,0,NONCE_SZ);
    rc = mk_esp_http_acme_req_rsp(&actx->hCfg, &actx->mkrspdata);
    if ( rc < 0 ) {
        MK_LOG(LOG_ERR, "%s(): Error rc=%d \n",__func__,rc);
        return -1;
    }

    //MK_LOG(LOG_INFO, "%s() received Replay-Nonce => %s \n", __func__,actx->mkrspdata.Replay_Nonce);
    MK_LOG(LOG_INFO, "%s() received Replay-Nonce Header\n", __func__);

    actx->mkrspdata.rsp_buff[actx->mkrspdata.rsp_rx_bytes] = 0; //NULL terminate, just in case, to be used as a string buffer
    return 0;
}


int mk_free_mbedtls_key_params(mk_acme_info * actx)
{
    mk_mbedtls_key_params *pmtls = NULL;
    if (!actx) {
        return -1;
    }

    pmtls = &actx->mtlsc;

    mbedtls_pk_free(&pmtls->acct_pkey);

    mbedtls_pk_free(&pmtls->cert_pkey);

    mbedtls_ctr_drbg_free(&pmtls->ctr_drbg_ctx);

    mbedtls_entropy_free(&pmtls->entropy_ctx);

    return 0;
}

int mk_init_mbedtls_key_params(mk_acme_info * actx)
{
    int ret = 0;
    unsigned int ori_task_priority = 0;
    unsigned int cur_task_priority = 0;
    mk_mbedtls_key_params *pmtls = NULL;

    if (!actx) {
        return -1;
    }
    pmtls = &actx->mtlsc; 

    MK_LOG(LOG_DEBUG,"%s() Entry ..... \n",__func__);

    //init crt_drbg: Counter mode Deterministic Random Byte Generator
    mbedtls_ctr_drbg_init(&pmtls->ctr_drbg_ctx);

    // init the entropy context
    mbedtls_entropy_init(&pmtls->entropy_ctx);

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
    MK_LOG(LOG_DEBUG,"%s() Try changing task priority from(%u) -> to(%u) \n",
                                   __func__,ori_task_priority,tskIDLE_PRIORITY);
    vTaskPrioritySet(NULL, tskIDLE_PRIORITY);
    MK_LOG(LOG_DEBUG,"%s() Task Prioirty after the change = %u \n",__func__, uxTaskPriorityGet(NULL));

    ret = mk_load_acme_keys(actx);

    //try to revert the task priority to original value reagrdless of the result of above call.
    cur_task_priority = uxTaskPriorityGet(NULL);
    if (cur_task_priority !=  ori_task_priority) {
       vTaskPrioritySet(NULL, ori_task_priority);
       MK_LOG(LOG_DEBUG,"%s() Reverted back task priority from(%u) -> to(%u)\n",
                            __func__, cur_task_priority, uxTaskPriorityGet(NULL));
    }

    //check the return value - ret from above mk_load_acme_keys() call.
    if (ret < 0) {
       MK_LOG(LOG_ERR,"%s() mk_load_acme_keys failed,  ret=%d \n",__func__, ret);
       return -1;
    }

     //MK_LOG(LOG_DEBUG,"acct_pkey[pk_ctx=%p, pk_info=%p, bitlen=%d getlen=%d] \n",
     //               actx->mtlsc.acct_pkey.pk_ctx, actx->mtlsc.acct_pkey.pk_info, 
     //               mbedtls_pk_get_bitlen(&actx->mtlsc.acct_pkey),mbedtls_pk_get_len(&actx->mtlsc.acct_pkey));

     //MK_LOG(LOG_DEBUG,"cert_pkey[pk_ctx=%p, pk_info=%p, bitlen=%d getlen=%d] %s \n",
     //              actx->mtlsc.cert_pkey.pk_ctx, actx->mtlsc.cert_pkey.pk_info,
     //              mbedtls_pk_get_bitlen(&actx->mtlsc.cert_pkey),mbedtls_pk_get_len(&actx->mtlsc.cert_pkey),
     //              mbedtls_pk_check_pair(&actx->mtlsc.acct_pkey,&actx->mtlsc.cert_pkey)==0?"same":" ");

    MK_LOG(LOG_DEBUG,"%s() Return ..... \n",__func__);
    return 0;
}

int mk_load_acme_keys(mk_acme_info * actx)
{
    int ret = 0;
    mk_acme_config *pacfg = NULL ; 
    mk_mbedtls_key_params *pmtls = NULL;
    unsigned int nbits = actx->pacfg->key_gen_sz_nbits ? actx->pacfg->key_gen_sz_nbits : DFT_KEY_NBITS;
    int exponent = 65537; //(2^16)+1
    time_t t1;
    time_t t2;

    if (!actx) {
      return -1;
    }

    pacfg = actx->pacfg;
    pmtls = &actx->mtlsc;

    //step1: mbedtls_pk_init()
    mbedtls_pk_init(&pmtls->acct_pkey);
    mbedtls_pk_init(&pmtls->cert_pkey);

    //step2: load or generate keys based on user request.
        // -- if key is given as file, load it using mbedtls_pk_parse_keyfile().
        // -- else if key is given in buffer load it using mbedtls_pk_parse_key()
        // -- else generate a key, using mbedtls_pk_setup/mbedtls_rsa_gen_key().
    t1 = time(NULL);
    MK_LOG(LOG_INFO,"\n%s() Loading/genrating keys - acme_pem_acct_key_data_source=%d time=%ld\n",
                       __func__,pacfg->acme_pem_acct_key_data_source,t1);


    // Initialize a PK context with the information given and allocates the type-specific PK subcontext.
    ret = mbedtls_pk_setup(&pmtls->cert_pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
       MK_LOG(LOG_ERR,"%s(Error) mbedtls_pk_setup failed for cert_pkey ret=-%x \n ", __func__,-ret);
       return -1;
    }

    MK_LOG(LOG_INFO,"\n%s() start generating nbits=%d cert_pkey ... \n ",__func__,nbits);
    // generate keypair into cert_pkey: using default callback for getting (pseudo-)random numbers with drbg context
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pmtls->cert_pkey), mbedtls_ctr_drbg_random, 
				  &pmtls->ctr_drbg_ctx, nbits, exponent);
    if (ret != 0) {
       MK_LOG(LOG_ERR,"%s(Error) mbedtls_rsa_gen_key failed for cert_pkey ret=-%x \n ", __func__,-ret);
       return -1;
    }
    t2 = time(NULL);

    //MK_LOG(LOG_INFO,"%s(Success) generating cert_pkey \n ",__func__);
    MK_LOG(LOG_INFO,"%s(Success) generating nbits=%d cert_pkey t2[%ld] - t1[%ld] = %ld secs \n\n",__func__,nbits,t2,t1,t2-t1);

    if (pacfg->acme_pem_acct_key_data_source == ACME_PEM_KEY_SRC_GENERATE) {

        t1 = time(NULL);

        // Initialize a PK context with the information given and allocates the type-specific PK subcontext.
        ret = mbedtls_pk_setup(&pmtls->acct_pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        if (ret != 0) {
	   MK_LOG(LOG_ERR,"%s(Error) mbedtls_pk_setup failed for acct_pkey ret=-%x \n ", __func__,-ret);
	   return -1;
        }

        MK_LOG(LOG_INFO,"%s() start generating nbits=%d acct_pkey ... \n ",__func__,nbits);

        // generate keypair into acct_pkey: using default callback for getting (pseudo-)random numbers with drbg context
        ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pmtls->acct_pkey), mbedtls_ctr_drbg_random, 
                                      &pmtls->ctr_drbg_ctx, nbits, exponent);
        if (ret != 0) {
	   MK_LOG(LOG_ERR,"%s(Error) mbedtls_rsa_gen_key failed for acct_pkey ret=-%x \n ", __func__,-ret);
	   return -1;
        }

        t2 = time(NULL);
        MK_LOG(LOG_INFO,"%s(Success) generating nbits=%d acct_pkey t2[%ld] - t1[%ld] = %ld secs \n ",__func__,nbits,t2,t1,t2-t1);

    }
    else if (pacfg->acme_pem_acct_key_data_source == ACME_PEM_KEY_SRC_PATH) {

       // ---------------------- account key as file ----------------------
       if (!pacfg->acct_key_pem_path) {
	   MK_LOG(LOG_ERR,"%s(Error) empty acct_key_pem_path file path \n ", __func__);
	   return -1;
       }

       if ((!pacfg->acct_key_passphrase) || (!pacfg->acct_key_passphrase_len)) {
	   MK_LOG(LOG_ERR,"%s(Error) empty acct_key_passphrase value \n ", __func__);
	   return -1;
       }

       ret = mbedtls_pk_parse_keyfile(&pmtls->acct_pkey, pacfg->acct_key_pem_path, pacfg->acct_key_passphrase);
       if (ret < 0)
       {
	   MK_LOG(LOG_ERR,"%s(Error) loading acct_pkey using mbedtls_pk_parse_keyfile file=%s ret=-%x \n ",
		      __func__,pacfg->acct_key_pem_path ,-ret);
	   return -1;
       }

       MK_LOG(LOG_INFO,"%s(Success) Loading acct_pkey from file=%s \n ",__func__,pacfg->acct_key_pem_path);

    }
    else {
       int slen = 0;
       if (pacfg->acme_pem_acct_key_data_source == ACME_PEM_KEY_SRC_EMBED_FILES) {

          // account key embedded pem data
	  pacfg->acct_key_pem_buf = (uint8_t *)acct_key_pem_start;
          pacfg->acct_key_pem_bytes = (acct_key_pem_end-acct_key_pem_start); 

	  MK_LOG(LOG_NOTICE,"%s(ACME_PEM_KEY_SRC_EMBED_FILES) \n", __func__);
       }

       if ((!pacfg->acct_key_pem_buf) || (!pacfg->acct_key_pem_bytes)) {
	   MK_LOG(LOG_ERR,"%s(Error) empty acct_key_pem_buf value \n ", __func__);
	   return -1;
       }

       if ((!pacfg->acct_key_passphrase) || (!pacfg->acct_key_passphrase_len)) {
	   MK_LOG(LOG_ERR,"%s(Error) empty acct_key_passphrase value \n ", __func__);
	   return -1;
       }

       slen = (int)strlen((char *)pacfg->acct_key_pem_buf);
       if (pacfg->acct_key_pem_bytes == slen) {
          // need to include the length of terminating null bytes when mbedtls_x509_crt_parse for parsing
          // pem data in a buffer
          //NOTE: In the case of embedded file as buffer the terminating null character is included already.
          pacfg->acct_key_pem_bytes += 1;
          MK_LOG(LOG_DEBUG , "%s() adding an extra byte for the terminating null byte to acct_key_pem_bytes\n",__func__);
       }

       // ---------------------- account key as buffer ----------------------
       ret = mbedtls_pk_parse_key(&pmtls->acct_pkey, pacfg->acct_key_pem_buf, pacfg->acct_key_pem_bytes, 
                                        (const unsigned char *)pacfg->acct_key_passphrase, pacfg->acct_key_passphrase_len);
       if(ret < 0)
       {
	   MK_LOG(LOG_ERR,"%s(Error) mbedtls_pk_parse_key loading acct_pkey from acct_key_pem_buf bytes=%d ret=-%x \n ",
		      __func__,pacfg->acct_key_pem_bytes,-ret);
	   return -1;
       }


       MK_LOG(LOG_INFO,"%s(Success) loading acct_pkey from acct_key_pem_buf len=%d \n ", 
                                  __func__,pacfg->acct_key_pem_bytes);
    }

    // Verify if it is RSA key and return otherwise. Just in case.
    if (!mbedtls_pk_can_do(&pmtls->acct_pkey, MBEDTLS_PK_RSA)) {
        MK_LOG(LOG_ERR,"%s(Error) acct_pkey is not an RSA key \n ", __func__);
        return -1;
    }

    //MBEDTLS_RSA_PKCS_V15
    //set to (default) RSAES-PKCS1-v1_5: older encryption/decryption scheme as first standardized in version 1.5 of PKCS #1
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pmtls->acct_pkey), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

    return 0 ;
}

int __mimik_free_acme_resources(mk_acme_info * actx)
{
   mk_json_free_directory_resource(&actx->dir_resource);
   mk_json_free_order_resp(&actx->order_resp);
   mk_json_free_finalize_resp(&actx->finalize_resp);
   mk_json_free_finalize_resp(&actx->finalize_location_resp);
   mk_json_free_authorizations_resp(&actx->authorizations_resp);
   mk_json_free_challenges_resp(&actx->challenge_resp);
   mk_free_mbedtls_key_params(actx);
   memset(actx,0,sizeof(mk_acme_info));
   return 0;
}

int __mimik_obtain_acme_certificate(mk_acme_info *actx)
{
   int rc = 0 ;
   int num_tries = 0;
   char * certificate_url = NULL;
   char *challenge_url = NULL;

   if ((!actx) || (!actx->pacfg) || (!actx->pacfg->acme_directory_url) || (!actx->pacfg->acme_account_url)) {
      MK_LOG(LOG_ERR, "%s(): Error inavlid parms for (actx->pacfg->acme_directory_url , acme_account_url)\n",__func__);
      return -1;
   }
   
   if ((!actx->pacfg->device_id)||(!actx->pacfg->client_id)||(!actx->pacfg->scope)) {
      MK_LOG(LOG_ERR, "%s(): Error inavlid parms for device_id client_id scope \n",__func__);
      return -1;
   }

   actx->kid_KeyId = actx->pacfg->acme_account_url;

   if ((actx->pacfg->key_gen_sz_nbits == 0)||(actx->pacfg->key_gen_sz_nbits > KEY_NBITS_2048)) {
      actx->pacfg->key_gen_sz_nbits = DFT_KEY_NBITS;
   }

   rc = mk_init_mbedtls_key_params(actx);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(): mk_init_mbedtls_key_params failed \n",__func__);
      return -1;
   }


/*
  ACME is structured as an HTTP-based application with the following         
   types of resources:                                                        
                                                                              
   o  Account resources, representing information about an account            
      (Section 7.1.2, Section 7.3)                                            
                                                                              
   o  Order resources, representing an account's requests to issue            
      certificates (Section 7.1.3)                                            
                                                                              
   o  Authorization resources, representing an account's authorization        
      to act for an identifier (Section 7.1.4)                                
                                                                              
   o  Challenge resources, representing a challenge to prove control of       
      an identifier (Section 7.5, Section 8)                                  
                                                                              
   o  Certificate resources, representing issued certificates                 
      (Section 7.4.2)

*/

  /*
   From rfc8555
   "Except for the directory resource, all ACME resources are addressed
   with URLs provided to the client by the server.  In POST requests
   sent to these resources, the client MUST set the "url" header
   parameter to the exact string provided by the server (rather than
   performing any re-encoding on the URL).  The server SHOULD perform
   the corresponding string equality check, configuring each resource
   with the URL string provided to clients and having the resource check
   that requests have the same string in their "url" header parameter.
   The server MUST reject the request as unauthorized if the string
   equality check fails."
*/

   MK_LOG(LOG_INFO, "%s(1): Start getting ACME directory resource object ...\n",__func__);

   //Step1: start with getting directory object from ACME server
   rc = mk_get_acme_directory_resource(actx);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(1): mk_get_acme_directory_resource failed \n\n",__func__);
      return -1;
   }

   MK_LOG(LOG_INFO, "%s(1): GET ACME directory resource object SUCCESS ...\n\n",__func__);

   //Step2: send http HEAD request to acme server using the newNonce URL
   //obtained in directory request response.
   MK_LOG(LOG_INFO, "%s(2): Start getting newNonce HEADER...\n",__func__);

   rc = mk_get_acme_new_nonce(actx, actx->dir_resource.newNonce);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(2): mk_get_acme_new_nonce failed \n",__func__);
      return -1;
   }

   MK_LOG(LOG_INFO, "%s(2): HEAD ACME newNonce response SUCCESS ...\n\n",__func__);

   // In this acme client release, we will skip the account creation or query
   // step and instead use the user supplied value as follows for KeyId in our
   // new order creation newOrder request.

   //Step3: Issue a new Order using the above nonce value
   // Submit order an with POST newOrder and expect a http return code of 201 -> order
   /*
       The client begins the certificate issuance process by sending a POST
       request to the server's newOrder resource.  The body of the POST is a JWS
       object whose JSON payload subset of the order object.

   All ACME requests with a non-empty body MUST encapsulate their payload in a
   JSON Web Signature (JWS) [RFC7515] object, signed using the account's 
   private key.

   */


   /*
       Once an account is registered, there are four major steps the client
       needs to take to get a certificate:
   1.  Submit an order for a certificate to be issued                         
   2.  Prove control of any identifiers requested in the certificate          
   3.  Finalize the order by submitting a CSR                                 
   4.  Await issuance and download the issued certificate
   */

   MK_LOG(LOG_INFO, "%s(3): Start POSTing newOrder request ...\n",__func__);

   rc = mk_post_acme_neworder_resource(actx);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(3): mk_post_acme_neworder_resource failed \n",__func__);
      return -1;
   }

   rc = mk_acme_check_resource_response_status(actx->order_resp.status);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(3): actx->order_resp.status error\n",__func__);
      return -1;
   }

   MK_LOG(LOG_INFO, "%s(3): POST ACME new order resource object SUCCESS ...\n\n",__func__);

   // --------------- beginning of authorizations and challenges -------------

   //Step4: send http HEAD request to acme server using the newNonce URL
   //obtained in directory request response.
   MK_LOG(LOG_INFO, "%s(4): Start getting newNonce HEADER...\n",__func__);
   rc = mk_get_acme_new_nonce(actx, actx->dir_resource.newNonce);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(4): mk_get_acme_new_nonce failed \n",__func__);
      return -1;
   }
   MK_LOG(LOG_INFO, "%s(4): HEAD ACME newNonce response SUCCESS ...\n\n",__func__);

   MK_LOG(LOG_INFO, "%s(4a): Start POSTing authorizations resource ...\n",__func__);
   rc = mk_post_acme_authorizations_resource(actx);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(4a): mk_post_acme_authorizations_resource failed \n",__func__);
      return -1;
   }

   rc = mk_acme_check_resource_response_status(actx->authorizations_resp.status);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(4a): actx->authorizations_resp.status error\n",__func__);
      return -1;
   }

   MK_LOG(LOG_INFO, "%s(4a): POST ACME new authorizations resource object SUCCESS ...\n\n",__func__);

   //Step4d: POST challenge and Wait till status is "valid" for challenge response.
   #define C_NUM_TRIES 5
   #define C_WAIT_SECS 2

   challenge_url = actx->tx_msg.mk_challenge_url ;  //For the first time use the challenge uri formed after authorization
   for (num_tries = 0; num_tries < C_NUM_TRIES; num_tries++) {

      MK_LOG(LOG_INFO, "%s(4c): Start getting newNonce HEADER...\n",__func__);
      rc = mk_get_acme_new_nonce(actx, actx->dir_resource.newNonce);
      if ( rc < 0 ) {
	 MK_LOG(LOG_ERR, "%s(4c): mk_get_acme_new_nonce failed \n",__func__);
	 return -1;
      }
      MK_LOG(LOG_INFO, "%s(4c): HEAD ACME newNonce response SUCCESS \n\n",__func__);

      MK_LOG(LOG_INFO, "%s(4c): Start POSTing challenege resource ...\n",__func__);
      rc = mk_post_acme_challenges_resource(actx, challenge_url, NULL);
      if ( rc < 0 ) {
	 MK_LOG(LOG_ERR, "%s(4c): mk_post_acme_challenges_resource failed \n",__func__);
	 return -1;
      }
      MK_LOG(LOG_INFO, "%s(4c): POST ACME challenge resource object SUCCESS ...\n\n",__func__);

      rc = mk_acme_check_resource_response_status(actx->challenge_resp.challenges.status);
      if ( rc < 0 ) {
	 MK_LOG(LOG_ERR, "%s(4c): actx->challenge_resp.challenges.status error\n",__func__);
	 return -1;
      }

      if (strcasecmp(actx->challenge_resp.challenges.status, "valid") == 0) {

	  MK_LOG(LOG_INFO, "\n%s(4c) - challenge complete : status=%s \n",__func__,actx->challenge_resp.challenges.status);
	  break;
      }

      // In re-trying (polling) for challenge completion, use the newly obtained challenge uri if available.
      if (actx->challenge_resp.challenges.url) {
         challenge_url = actx->challenge_resp.challenges.url;
      }

      MK_LOG(LOG_INFO, "\n%s(4c) - Re-try and check for challenge completion status after %d seconds, num_tries=%d \n",
			    __func__,C_WAIT_SECS,num_tries);
      sleep(C_WAIT_SECS);

   } //end of for loop

   // -------------------- end of authorizations and challenges -------------

   //Step5: send http HEAD request to acme server using the newNonce URL
   //obtained in directory request response.
   MK_LOG(LOG_INFO, "%s(5): Start getting newNonce HEADER...\n",__func__);
   rc = mk_get_acme_new_nonce(actx, actx->dir_resource.newNonce);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(5): mk_get_acme_new_nonce failed \n",__func__);
      return -1;
   }
   MK_LOG(LOG_INFO, "%s(5): HEAD ACME newNonce response SUCCESS ...\n\n",__func__);

   //Step5:  finalize: A URL that a CSR must be POSTed to once all of the order's
   //        authorizations are satisfied to finalize the order.
   //        The result of a successful finalization will be the
   //        population of the certificate URL for the order.

/* comments from rfc8555:

   "Once the client believes it has fulfilled the server's requirements,
   it should send a POST request to the order resource's finalize URL.
   The POST body MUST include a CSR:

*/
   MK_LOG(LOG_INFO, "%s(5): Start POSTing finalize resource with CSR ...\n",__func__);

   rc = mk_post_acme_finalize_resource(actx);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(5): mk_post_acme_finalize_resource failed \n",__func__);
      return -1;
   }

   rc = mk_acme_check_resource_response_status(actx->finalize_resp.status);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(5): mk_post_acme_finalize_resource status error\n",__func__);
      return -1;
   }

   MK_LOG(LOG_INFO, "%s(5): POST ACME new finalize resource object SUCCESS ...\n\n",__func__);


   //Step5b: Wait till status is "valid" and certficate url is available from server.
   if ( (actx->finalize_resp.certificate) && (actx->finalize_resp.status) &&
        (strcasecmp(actx->finalize_resp.status, "valid") == 0) ) {

       certificate_url = actx->finalize_resp.certificate;

       MK_LOG(LOG_INFO, "\n%s(5) - certificate available: status=%s \n",__func__,actx->finalize_resp.status);

   }else {
      // status : "pending"
      #define CERT_NUM_TRIES 10
      #define CERT_WAIT_SECS 2

      //poll using location url obtained earlier until server responds with certificate url and available status.
      for (num_tries = 0; num_tries < CERT_NUM_TRIES; num_tries++) {

         MK_LOG(LOG_INFO, "\n%s(5b) - Re-try and check for certificate availability after %d seconds, num_tries=%d \n",
                               __func__,CERT_WAIT_SECS,num_tries);
         sleep(CERT_WAIT_SECS);
	 MK_LOG(LOG_INFO, "%s(5b): Start getting newNonce HEADER...\n",__func__);
	 rc = mk_get_acme_new_nonce(actx, actx->dir_resource.newNonce);
	 if ( rc < 0 ) {
	    MK_LOG(LOG_ERR, "%s(5b): mk_get_acme_new_nonce failed \n",__func__);
	    return -1;
	 }
	 MK_LOG(LOG_INFO, "%s(5b): HEAD ACME newNonce response SUCCESS \n\n",__func__);
	 rc = mk_post_acme_location_url_for_certificate_resource(actx);
	 if ( rc < 0 ) {
	    MK_LOG(LOG_ERR, "%s(5b): mk_post_acme_location_url_for_certificate_resource failed \n",__func__);
	    return -1;
	 }

	 rc = mk_acme_check_resource_response_status(actx->finalize_location_resp.status);
	 if ( rc < 0 ) {
	    MK_LOG(LOG_ERR, "%s(5b): mk_post_acme_finalize_resource poll status error\n",__func__);
	    return -1;
	 }

         MK_LOG(LOG_INFO, "%s(5b): POST ACME location resource object SUCCESS ...\n\n",__func__);
	 if (strcasecmp(actx->finalize_location_resp.status, "valid") == 0) {

	     certificate_url = actx->finalize_location_resp.certificate;

	     MK_LOG(LOG_INFO, "\n%s(5b) - certificate available: status=%s \n",__func__,actx->finalize_location_resp.status);
             break;
	 }

      } //end of for loop

   }

   if (!certificate_url) {
      //unlikley but check in case if repeated polling still could not get the url
      MK_LOG(LOG_ERR, "%s(5b): certificate_url is empty\n",__func__);
      return -1;
   }

   //Step6: send http HEAD request to acme server using the newNonce URL
   //obtained in directory request response.
   MK_LOG(LOG_INFO, "%s(6): Start getting newNonce HEADER...\n",__func__);

   rc = mk_get_acme_new_nonce(actx, actx->dir_resource.newNonce);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(6): mk_get_acme_new_nonce failed \n",__func__);
      return -1;
   }

   MK_LOG(LOG_INFO, "%s(6): HEAD ACME newNonce response SUCCESS \n\n",__func__);

   //Step6: POST to certificate resource url obtained in finalize response and
   //download certificate from acme server.
   MK_LOG(LOG_INFO, "%s(6): Start POSTing certificate resource and Download the certificate...\n",__func__);
   rc = mk_post_acme_certificate_resource(actx, certificate_url);
   if ( rc < 0 ) {
      MK_LOG(LOG_ERR, "%s(6): mk_post_acme_certificate_resource failed \n",__func__);
      return -1;
   }

   MK_LOG(LOG_INFO, "\n\n%s(FINISHED): !!!! Certificate Download SUCCESS !!!! \n\n",__func__);

   return rc ;
}

int mimik_acme_client_obtain_certificate(mk_acme_config *pacfg, mk_acme_certificate *cert_resp)
{
   int rc = 0;

   mk_acme_info *actx = &g_acme_ctx;

   memset(actx,0,sizeof(mk_acme_info));
   actx->pacfg = pacfg;
   actx->cert_resp = cert_resp;

   MK_LOG(LOG_INFO, "\n ......  %s(): starting ...... \n",__func__);

   rc = __mimik_obtain_acme_certificate(actx);

   // MK_LOG(LOG_DEBUG, "%s(): calling __mimik_free_acme_resources rc=%d ... \n",__func__,rc);

   __mimik_free_acme_resources(actx);

   MK_LOG(LOG_INFO, "\n.....  %s(): finished rc=%d .... \n\n",__func__,rc);

   return rc;
}
