/*
 * mimik technology inc Copyright (c) 2020 Right Reserved
 */

/*
 *  File:   mk_services_data.h
 *  Author: Varadhan Venkataseshan
 */

#ifndef __MK_SERVICES_DATA__H__
#define __MK_SERVICES_DATA__H__

// JSON: service record object abstract data types are stored in c structures
// with a structure name beginning __ and then followed by name found in the
// service record. For example a "data" object with multiple elements with in
// it is represented in a c structure as struct __data data;
// where struct __data{ ... }; will have the members found in data.

typedef struct __account {
     char *id;
     char *self;
}__account;

typedef struct __url {
  char *href;
}__url;

typedef struct __address {
     char *type;
     __url url;
     unsigned short routingPort;
}__address;

typedef struct __attributes {
     char *name;
     char *value;
}__attributes;

typedef struct __characteristics {
     char *name;
     char *value;
}__characteristics;

typedef struct __tenant {
     char *id;
     char *self;
}__tenant;

typedef struct __location{
     double coordinates[2];
     char *origin ;
     char *type ;
}__location;

typedef struct __services {
    char *id;
    char *self;
    char *serviceType;
    __tenant tenant;
}__services;

typedef struct __data {

   __account account;

  //"addresses":
  #define MAX_ADDRESS_ARRAY_COUNT 4
   int address_array_count;
   __address addresses[MAX_ADDRESS_ARRAY_COUNT+1];  

  //"attributes":
  #define MAX_ATTRIBUTES_ARRAY_COUNT 5
   int attributes_array_count;
   __attributes attributes[MAX_ATTRIBUTES_ARRAY_COUNT+1];

   //"characteristics":
  #define MAX_CHARACTERISTICS_ARRAY_COUNT 10
   int characteristics_array_count;
   __characteristics characteristics[MAX_CHARACTERISTICS_ARRAY_COUNT+1];

   char *createdAt;
   char *id;
   char *localLinkNetworkId;
   __location location;
   char *networkAddress;
   char *rolesInCluster;
   char *self;

   //"services":
   #define MAX_SERVICES_ARRAY_COUNT 10
   int services_array_count;
   __services services[MAX_SERVICES_ARRAY_COUNT+1];

   // There seems to be one extra tenant variable in data other than in services.
   __tenant tenant;
  
   char *updatedAt;

}__data;

typedef struct service_records {
   char *type;  //"network"
  #define MAX_DATA_ARRAY_COUNT 10
   int data_array_count;
   __data data[MAX_DATA_ARRAY_COUNT+1]; //Array of data records:  __data data[data_array_count];
  
}service_records;

#endif  //__MK_SERVICES_DATA__H__
