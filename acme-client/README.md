                          mimik RTOS acme client Sdk
                          ==========================

mimik Automatic Certificate Management Environment (ACME) client library:

---------
Overview
---------

mimik's ACME client library provides a facility to connect and transact with
ACME server and successfully obtain X.509 certificate as per ACME rfc8555
specification.

   Except for the directory resource, all ACME resources are addressed with
URLs provided to the client by the server.  ACME is structured as an HTTP-based
application with the following types of resources.
                                                                              
   -  Account resources: represents information about an account.

   -  Order resources: represents an account's requests to issue
      certificates.

   -  Authorization resources: represents an account's authorization to
      act for an identifier

   -  Challenge resources: represents a challenge to prove control of an
      identifier.

   -  Certificate resources: represents issued certificates.


Our ACME client basically works as follows: 
------------------------------------------

    ACME client first need to obtain directory object from ACME server to
configure themselves with the right URLs (provided in the directory JSON object
for each ACME operation. This is the only URL needed to configure clients.

It first sends a directory request to acme server and on successful response 
obtains the relevant URL for various resources such as:
newNonce, newAccount, newOrder, newAuthz(New authorization), revokeCert(Revoke
certificate),  keyChange (Key change)
  
After an account is registered by the client with ACME server, it takes the
following steps to get a certificate:
   1.  Submit an order for a certificate to be issued
   2.  Prove control of any identifiers requested in the certificate
   3.  Finalize the order by submitting a CSR
   4.  Await issuance and download the issued certificate

   init stage: creates two private keys one is for account key, and another
private key is used for CSR generation. If a user of the this facility passes
an account key, it uses that instead of creating a new private key.
    
   Step1: starts with getting directory object from ACME server

   Step2: send http HEAD request to acme server using the newNonce URL
          obtained in directory request response.

   Step3: Create a new Account in acme server or query an existing account if
          any with "onlyReturnExisting" option by sending a POST request for
          newAccount resource and obtain Account URL to be used as a KeyId(kid) in
          the next and an important step of creating a new order.  

   NOTE: For now, in this first acme client release, we will skip the
   account creation or query step and instead use the user supplied
   value for KeyId in our new order creation newOrder request.

   Step4: Issue a new Order using the above nonce value
          Submit order with POST newOrder and expect a http return code of 201 -> order
  
     The client begins the certificate issuance process by sending a POST
request to the server's newOrder resource.  All ACME requests with a non-empty
body encapsulate their payload in a JSON Web Signature (JWS) [RFC7515] object,
signed using the account's private key.

     mimik's default values for new order request:
        "protected":
        ==========
       "alg": "RS256" : may be allow to select an algorithm such as RS256 or ES256
       "kid": if kid_KeyId is given by user or use the above default MK_ACME_DFT_KID_ACCOUNT_URL,
       "nonce": use the Replay_Nonce obtained from previous call newNonce,
       "url": use the newOrder url obtained in directory response (http://192.168.1.74:8088/acme/v2/orders) 
        "payload":
        =========
        -- we are using two type value pairs for identifier.
        -- We are using "dns" for identifier "type"
        -- identifier "value" is configurable
        char * Identifier_Value1;
        char * Identifier_Value2;
        #define DFT_IDENTIFIER_TYPE_VALUE1 "*.example.com"
        #define DFT_IDENTIFIER_TYPE_VALUE2 "example.com"
        -- We are not presently using the optional "notBefore" and "notAfter" JSON fields.


   Step5: send http HEAD request to acme server using the newNonce URL
          obtained in directory request response.

   NOTE: In the first iteration of the acme client, challenge verification is
   not implemented.

   Step6: finalize: A URL that a CSR must be POSTed to once all of the order's
          authorizations are satisfied to finalize the order.
          The result of a successful finalization will be the
          population of the certificate URL for the order.
  NOTE: For ACME, as per rfc8555, "finalize" request -- "payload" -- should
  include Certificate Signing Request (CSR) data generated from client key in
  Distinguished Encoding Rules(DER) format.

   Step7: send http HEAD request to acme server using the newNonce URL
          obtained in directory request response.

   Step8: POST to certificate resource url obtained in finalize response and 
          download certificate from acme server.


--------------------------
Source code organization:
--------------------------

mimik-rtos-sdk/acme-client/include/ and mimik-rtos-sdk/acme-client/src/ contains the following:
- mimik_acme_client.h and mimik_acme_client.c

  Only a single library mimik_acme_client_obtain_certificate() need to called
to obtain client certificate from a configured acme server.

An example code snipped is given below:

   mk_acme_config acfg = { 0 };  //declare and define a config structure
   //NOTE do not allocate for mk_acme_certificate in stack, either use static or memory from heap.
   static mk_acme_certificate acerts;  //declare and define memory for downloading structure.

   acfg.acme_directory_url = "http://192.168.1.74:8088/acme/v2/directory";
   int rc = mimik_acme_client_obtain_certificate(&acfg, &acerts);
   if ( rc < 0 ) {
        printf("mimik_acme_client_obtain_certificate failed.\n");
   }
   else {
        printf("Successfully downloaded certificate from acme server \n");
   }

  mimik_acme_client_test.c : example test function that downloads a certificate from an acme server,  
                             using mimik_acme_client_obtain_certificate() library function.


---------------------------------------------------------------------------------
main mimik acme client certificate function and structure details:
---------------------------------------------------------------------------------
mimik_acme_client.h and mimik_acme_client.c provides an ACME client facility
to connect and transact with ACME server and successfully obtain X.509
 certificate as per ACME http rules provided in rfc8555

mk_acme_config is main ENTRY config to use the acme client facility:

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

  #define DFT_IDENTIFIER_TYPE_VALUE1 "*.example.com"
  char * Identifier_Value1;
  #define DFT_IDENTIFIER_TYPE_VALUE2 "example.com"
  char * Identifier_Value2;

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

---------------------------------------------------------------------------------
