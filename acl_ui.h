#ifndef __ACL_UI__
#define __ACL_UI__

#include <stdbool.h>
#include <stdint.h>


/* This file defines the User Interface to Use ACL library*/
typedef struct access_list_ access_list_t;

access_list_t *
access_list_create (const char **,  int n_acl_entries);

bool 
access_list_evaluate1 (access_list_t *access_list, char *ip_hdr);

bool 
access_list_evaluate2 (access_list_t *access_list, 
                                    uint16_t l3proto,
                                    uint16_t l4roto,
                                    uint32_t src_addr,
                                    uint32_t dst_addr,
                                    uint16_t src_port,
                                    uint16_t dst_port);

void 
access_list_destroy (access_list_t *access_list);

void 
access_list_show (access_list_t *access_list);

#endif 