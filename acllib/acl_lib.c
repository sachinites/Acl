#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include "../mtrie/mtrie.h"
#include "acl_lib.h"
#include "acl_lib_util.h" 

access_list_t *
access_list_lib_create (const char **acl_entry_list,  int n_acl_entries) {

    int i;
    acl_entry_t *acl_entry;
    const char *acl_entry_str;

    if (!n_acl_entries) return NULL;

    acl_entry_t **acl_entry_temp = (acl_entry_t **)calloc (n_acl_entries, sizeof (acl_entry_t *));

    for (i = 0; i < n_acl_entries; i++) {

        acl_entry_str = acl_entry_list[i];

        if ((acl_entry_temp[i] = acl_entry_lib_rule_str_parse (acl_entry_str))) {

            printf ("Error : %s : Failed to Parse acl_entry \n   %s\n", __FUNCTION__, acl_entry_str);
            i--;
            while (i >= 0) {
                acl_entry_free (acl_entry_temp[i]);
                i--;
            }
            free (acl_entry_temp);
            return NULL;
        }
    }

    access_list_t *access_list = (access_list_t *)calloc(1, sizeof (access_list_t));
    access_list->mtrie = (mtrie_t *)calloc(1, sizeof (mtrie_t));
    init_mtrie(access_list->mtrie, ACL_PREFIX_LEN, NULL);

    for (i = 0; i < n_acl_entries; i++) {

        acl_compile (acl_entry_temp[i]);
        acl_entry_install (access_list, acl_entry_temp[i]);
        acl_entry_free (acl_entry_temp[i]);
        acl_entry_temp[i] = NULL;
    }

    free (acl_entry_temp);
    return access_list;
}

void 
acl_entry_free (acl_entry_t *acl_entry) {

    if (acl_entry->tcam_sport_prefix) 
        free (acl_entry->tcam_sport_prefix);
    if (acl_entry->tcam_sport_wcard) 
        free (acl_entry->tcam_sport_wcard);

    if (acl_entry->tcam_dport_prefix) 
        free (acl_entry->tcam_dport_prefix);
    if (acl_entry->tcam_dport_wcard) 
        free (acl_entry->tcam_dport_wcard);

    free (acl_entry);
}


void
acl_compile (acl_entry_t *acl_entry) {

    uint8_t proto_layer = 0;

    assert(!acl_entry->tcam_src_addr_prefix);
    assert(!acl_entry->tcam_src_subnet_mask_prefix);

    assert(!acl_entry->tcam_dst_addr_prefix);
    assert(!acl_entry->tcam_dst_subnet_mask_prefix);

    if (acl_entry->proto == ACL_PROTO_ANY) {
        /* User has feed "any" in place of protocol in ACL */
        /* Fill L4 proto field and L3 proto field with Dont Care */
        acl_entry->tcam_l4proto_wcard = 0xFFFF; 
        acl_entry->tcam_l3proto_wcard = 0xFFFF; 
        goto SRC_ADDR;
    }

    proto_layer = tcpip_protocol_classification(
                                    (uint16_t)acl_entry->proto);

    /* Transport Protocol 2 B*/
    if (proto_layer == TRANSPORT_LAYER ||
         proto_layer == APPLICATION_LAYER) {

        acl_entry->tcam_l4proto_prefix = htons((uint16_t)acl_entry->proto);
        acl_entry->tcam_l4proto_wcard = 0;
    }
    else {
        acl_entry->tcam_l4proto_wcard = 0xFFFF;
    }

    /* Network Layer Protocol 2 B*/
    if (proto_layer == NETWORK_LAYER) {
     /* Protocol 2 B*/
        acl_entry->tcam_l3proto_prefix = htons((uint16_t)acl_entry->proto);
        acl_entry->tcam_l3proto_wcard = 0; 
    }
    else {
        acl_entry->tcam_l3proto_wcard = 0xFFFF;
    }

SRC_ADDR:

    acl_entry->tcam_src_addr_prefix =
        htonl(acl_entry->src_addr & acl_entry->src_subnet_mask);
    acl_entry->tcam_src_subnet_mask_prefix =
        htonl(~acl_entry->src_subnet_mask);

    /* Src Port Range */
    if (!acl_entry->tcam_sport_prefix)
    {
        acl_entry->tcam_sport_prefix = (uint16_t(*)[MAX_PFX_WC_ARRAY_LEN])
            calloc(1, sizeof(uint16_t) * sizeof(*acl_entry->tcam_sport_prefix));
    }
    else
    {
        memset(acl_entry->tcam_sport_prefix, 0,
               sizeof(uint16_t) * sizeof(*acl_entry->tcam_sport_prefix));
    }

    if (!acl_entry->tcam_sport_wcard)
    {
        acl_entry->tcam_sport_wcard = (uint16_t(*)[MAX_PFX_WC_ARRAY_LEN])
            calloc(1, sizeof(uint16_t) * sizeof(*acl_entry->tcam_sport_wcard));
    }
    else
    {
        memset(acl_entry->tcam_sport_wcard, 0,
               sizeof(uint16_t) * sizeof(*acl_entry->tcam_sport_wcard));
    }

    if (acl_entry->sport.lb == 0 &&
        acl_entry->sport.ub == 0)
    {

        acl_entry->tcam_sport_count = 1;
        (*acl_entry->tcam_sport_prefix)[0] = 0;
        (*acl_entry->tcam_sport_wcard)[0] = 0xFFFF;
    }
    else
    {
        range2_prefix_wildcard_conversion(
            acl_entry->sport.lb,
            acl_entry->sport.ub,
            acl_entry->tcam_sport_prefix,
            acl_entry->tcam_sport_wcard,
            (int *)&acl_entry->tcam_sport_count);
    }

DST_ADDR:

    /* Dst ip Address & Mask */
    acl_entry->tcam_dst_addr_prefix =
        htonl(acl_entry->dst_addr & acl_entry->dst_subnet_mask);
    acl_entry->tcam_dst_subnet_mask_prefix =
        htonl(~acl_entry->dst_subnet_mask);


    /* Dst Port Range */
    if (!acl_entry->tcam_dport_prefix) 
    {
        acl_entry->tcam_dport_prefix = (uint16_t(*)[MAX_PFX_WC_ARRAY_LEN])
            calloc (1, sizeof(uint16_t) * sizeof(*acl_entry->tcam_dport_prefix));
    }
    else 
    {
        memset(acl_entry->tcam_dport_prefix, 0, 
            sizeof(uint16_t) * sizeof(*acl_entry->tcam_dport_prefix));
    }

    if (!acl_entry->tcam_dport_wcard)
     {
        acl_entry->tcam_dport_wcard = (uint16_t(*)[MAX_PFX_WC_ARRAY_LEN])
            calloc (1, sizeof(uint16_t) * sizeof(*acl_entry->tcam_dport_wcard));
    }
    else {
        memset(acl_entry->tcam_dport_wcard, 0, 
            sizeof(uint16_t) * sizeof(*acl_entry->tcam_dport_wcard));
    }

    if (acl_entry->dport.lb == 0 && 
         acl_entry->dport.ub == 0 ) {
            
            acl_entry->tcam_dport_count = 1;
            (*acl_entry->tcam_dport_prefix)[0] = 0;
            (*acl_entry->tcam_dport_wcard)[0] = 0xFFFF;
    }
    else {      
        range2_prefix_wildcard_conversion(
            acl_entry->dport.lb,
            acl_entry->dport.ub, 
            acl_entry->tcam_dport_prefix,
            acl_entry->tcam_dport_wcard, 
            (int *)&acl_entry->tcam_dport_count);
    }

     acl_entry->hit_count = 0;
     acl_entry->tcam_total_count = 0;
}



void 
acl_entry_install (access_list_t *access_list, acl_entry_t *acl_entry) {

    
}