/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File: mimik_acme_client.h
 *  Author: Varadhan Venkataseshan
 */

#ifndef __MIMIK_ACME_CLIENT_H__
#define __MIMIK_ACME_CLIENT_H__

// mimik Automatic Certificate Management Environment (ACME) client library:
// mimik_acme_client.h and mimik_acme_client.c provides an ACME client facility
// to connect and transact with ACME server and successfully obtain X.509
// certificate as per ACME http rules provided in rfc8555

//mk_acme_config is main ENTRY config to use the acme client facility:
typedef struct mk_acme_config {

  // NOTE: acme_directory_url is a MANDATORY parameter
  // The acme client does NOT use any default value for acme_directory_url.
  // The user of acme client need to set this member before passing the argument to mimik_acme_client_obtain_certificate();
  // It is of the form: http://server_address:server_port/acme/v2/directory
  // For example: "http://192.168.1.74:8088/acme/v2/directory"

  char * acme_directory_url; //full acme server directory url - http://hostname:port/path

  // full pre-created acme account url, include full path
  // mimik_acme_client does not create account and expects use of the library to provide acme account url
  char * acme_account_url;

  char * device_id;  //device_id of the order identifier
  char * client_id;  //client_id of the order identifier
  char * scope;      //scope of the order identifier

  #define KEY_NBITS_2048 2048
  #define KEY_NBITS_1024 1024
  #define DFT_KEY_NBITS KEY_NBITS_1024
  unsigned int key_gen_sz_nbits; //size of key used when generating keypair

  // There are four options to provide account key
  //    option-1: Generate a key to be used
  // or option-2: as a readable file name with path
  // or option-3: as pointer to a buffer containing the data
  // or option-4: store the keys in the mentioned default files for automatic loading
  #define ACME_PEM_KEY_SRC_GENERATE    0
  #define ACME_PEM_KEY_SRC_PATH        1
  #define ACME_PEM_KEY_SRC_BUF         2
  #define ACME_PEM_KEY_SRC_EMBED_FILES 3
  char acme_pem_acct_key_data_source;
  char *acct_key_pem_path;  // acct key pem data as a file
  unsigned char *acct_key_pem_buf; // acct key pem data in a buffer
  int acct_key_pem_bytes;  // size of acct key pem data
  char *acct_key_passphrase;  // account key access pasword or pass_phrase for additional protection
  int acct_key_passphrase_len; // size of passphrase

  // certificate key is always generated.
  char *cert_key_passphrase;  // key creation pasword or pass_phrase for additional protection
  int cert_key_passphrase_len; // size of passphrase

}mk_acme_config;

typedef struct mk_acme_certificate {

   #define MAX_CERTIFICATE_SZ 4096
   //copy of the downloaded certificate
   int  cert_pem_len;
   char certificate_pem[MAX_CERTIFICATE_SZ+1]; //PEM format

   int  pri_key_pem_len;
   char pri_key_pem[MAX_CERTIFICATE_SZ+1];  //PEM format

   //int  csr_der_len;
  //DER (Distinguished Encoding Rules) binary encoded format
   //char csr_der[MAX_CERTIFICATE_SZ+1]; //DER format

}mk_acme_certificate;

/**
 * @brief   Automatic Certificate Management Environment (ACME) client:
 *          mimik_acme_client_obtain_certificate() function provides an ACME client facility
 *          to connect and transact with ACME server and successfully obtain X.509
 *          certificate as per ACME http rules provided in rfc8555.
 *  
 *
 * @param[in]   pacfg pointer to a filled mk_acme_config as briefed. [mandatory]

 * @param[out]  cert_resp pointer to mk_acme_certificate where certificate, and private
 *              key data is returned if provided [optional]
 *                   
 *              NOTE: Since mk_acme_certificate contains large buffer, do not 
 *              create mk_acme_certificate as stack variable. Instead either use
 *              static mk_acme_certificate res; or allocate memory using malloc
 *              for mk_acme_certificate
 *
 * @return      returns 0 on success and -1 on error
 */
int mimik_acme_client_obtain_certificate(mk_acme_config *pacfg, mk_acme_certificate *cert_resp);

#endif  //__MIMIK_ACME_CLIENT_H__
