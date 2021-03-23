/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File:   mk_tls_https_request.h
 *  Author: Varadhan Venkataseshan
 */

#ifndef __MK_TLS_HTTPS_REQ_H__
#define __MK_TLS_HTTPS_REQ_H__

// mk_tls_https_req.h and mk_tls_https_req.c provides an https interface client
// stub that utilizes mbedtls TLS/SSL library.It provides a facility to connect
// and transact securely via https with edge supernode using mimik supported
// REST API's and client certificates.

typedef void (*rx_msg_callback)(unsigned char *rxmsg, int msglen);

typedef struct mk_https_req {

//#define DFT_HTTPS_PORT 4433
#define DFT_HTTPS_PORT 8084
  unsigned short int port; //server port

  char *https_hostname; // peer node's ipv4 or hostname string to conenct to using TCP/IP

  #define DFT_CERTIFICATION_COMMON_NAME_HOST "localhost"
  char *CN_hostname; // Certificate Common Name to use for SSL/TLS certificate verification purpose

#define PATH_TENANTS_ME_SERVICES "/tenants/me/services"
#define PATH_SLASH "/"
  char *https_path; // HTTP Path, if not set, default is `/`

  char non_blocking;  //default is blocking client

  #define PEM_KEY_SRC_PATH        1
  #define PEM_KEY_SRC_BUF         2
  #define PEM_KEY_SRC_EMBED_FILES 3
  char pem_ca_cert_data_source; //specific for ca_cert
  char pem_client_key_data_source; //specific for client_key
  char pem_client_cert_data_source; //specific for client_cert

  // There are three options to provide client certificate, authority, and  key data
  //    option-1: as a readable file name with path
  // or option-2: store the keys in the mentioned default files for automatic loading
  // or option-3: as pointer to a buffer containing the data

  // The following default files are embedded as binary data in 
  // and is available to the component and the file contents will be 
  // contents will be added to the .rodata section in flash, and are available via symbol names
  // https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html#embedding-binary-data

  #define DFT_CA_CERTIFICATE_PEM_FILE      "ca_cert.pem"
  #define DFT_CLIENT_KEY_PEM_FILE          "client_key.pem"
  #define DFT_CLIENT_CERTIFICATE_PEM_FILE  "client_cert.pem"
  char *ca_cert_pem_path;  // certificate Authority pem data as a file
  unsigned char *ca_cert_pem_buf; // Certificate Authority pem data in a buffer
  int ca_cert_pem_bytes;  // length of Certificate Authority pem data

  char *client_key_pem_path;  // Client Certificate pem data as a file
  unsigned char *client_key_pem_buf; // Client Certificate pem data in a buffer
  int client_key_pem_bytes;  // size of Client Certificate pem data

  char *client_cert_pem_path;  // Client Certificate pem data as a file
  unsigned char *client_cert_pem_buf; // Client Certificate pem data in a buffer
  int client_cert_pem_bytes;  // size of Client Certificate pem data

  #define DFT_HTTPS_TIMEOUT_SEC  180
  int timeoutsec;

  rx_msg_callback rx_cbk_fn;  //registered function to call after receiving the response message in full

} mk_https_req;

typedef struct mk_response_data {
   char *rsp_buff;   // buffer to fill the response
   int  rsp_max_buff_sz;  // max size of the buffer
   int  rsp_rx_bytes;  // actual received bytes
   int  content_length; // length mentioned in http content_length
}mk_response_data;

/**
 * @brief mimik_tls_https_client_req_rsp prepares and sends http/https request as 
 *        directed in mk_https_req and returns the recived response message.
 *
 * @param[in]   preq        mk_https_req for the client. [mandatory]
 * @param[in]   prspd       pointer to struct mk_response_data to fill rx data [mandatory]
 * @param[out]  prspd       pointer to struct mk_response_data where rxdata info is filled.
 * @return                returns the length of received message on success and -1 on error
 */
int mimik_tls_https_client_req_rsp(mk_https_req *preq, mk_response_data *prspd);

#endif  //__MK_TLS_HTTPS_REQ_H__
