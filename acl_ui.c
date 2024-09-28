#include <stdlib.h>
#include "acl_ui.h"
#include "acllib/acl_lib.h"

access_list_t *
access_list_create (const char **,  int n_acl_entries) {


    return NULL;
}

bool 
access_list_evaluate1 (access_list_t *access_list, char *ip_hdr, char *transport_hdr) {

    return false;
}

bool 
access_list_evaluate2 (access_list_t *access_list, 
                                    uint16_t l3proto,
                                    uint16_t l4roto,
                                    uint32_t src_addr,
                                    uint32_t dst_addr,
                                    uint16_t src_port,
                                    uint16_t dst_port) {

    return false;
}

void 
access_list_destroy (access_list_t *access_list) {


}