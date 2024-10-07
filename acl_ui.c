#include <stdlib.h>
#include "acl_ui.h"
#include "acllib/acl_lib.h"

access_list_t *
access_list_create (const char **acl_entry_list,  int n_acl_entries) {

    if (!n_acl_entries) return NULL;
    return access_list_lib_create (acl_entry_list, n_acl_entries);
}

bool 
access_list_evaluate1 (access_list_t *access_list, char *ip_hdr) {

    return access_list_lib_evaluate1(access_list, ip_hdr);
}

bool 
access_list_evaluate2 (access_list_t *access_list, 
                                    uint16_t l3proto,
                                    uint16_t l4roto,
                                    uint32_t src_addr,
                                    uint32_t dst_addr,
                                    uint16_t src_port,
                                    uint16_t dst_port) {

    return access_list_lib_evaluate2 (access_list, 
                                            l3proto,
                                            l4roto,
                                            src_addr,
                                            dst_addr,
                                            src_port,
                                            dst_port); 
}

void 
access_list_destroy (access_list_t *access_list) {

    access_list_lib_destroy (access_list);
}


static void 
acl_entry_show_stats (void *data) {

    acl_entry_t *acl_entry = (acl_entry_t *)data;
    while (acl_entry) {
        acl_print (acl_entry);
        acl_entry = acl_entry->mtrie_next;    
    }
}

/* Importing the MTRIE lib function directly */
extern void
mtrie_app_data_traverse(
					mtrie_t *mtrie, 
                    void (*process_fn_ptr)( void *app_data) ) ;

void 
access_list_show (access_list_t *access_list) {

    mtrie_app_data_traverse (access_list->mtrie, acl_entry_show_stats);
}