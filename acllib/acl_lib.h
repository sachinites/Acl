#ifndef __ACL_LIB__
#define __ACL_LIB__

#include "acl_enums.h"
#include <stdint.h>

typedef struct mtrie_ mtrie_t;

/* Stores the info as read from CLI */
typedef struct acl_entry_{

    acl_action_t action;
    unsigned char *remark;
    
    acl_proto_t proto;
    uint16_t tcam_l4proto_prefix;
    uint16_t tcam_l4proto_wcard;
    uint16_t tcam_l3proto_prefix;
    uint16_t tcam_l3proto_wcard;

    /* Src Address*/
    uint32_t src_addr;
    uint32_t src_subnet_mask;
    uint32_t tcam_src_addr_prefix;
    uint32_t tcam_src_subnet_mask_prefix;

    /* Src Port*/
    struct {
        uint16_t lb, ub;
    } sport;
    uint8_t tcam_sport_count;
    uint16_t (*tcam_sport_prefix)[MAX_PFX_WC_ARRAY_LEN];
    uint16_t (*tcam_sport_wcard)[MAX_PFX_WC_ARRAY_LEN];

    /* Dest Address*/
    uint32_t dst_addr;
    uint32_t dst_subnet_mask;
    uint32_t tcam_dst_addr_prefix;
    uint32_t tcam_dst_subnet_mask_prefix;

    /* Dst Port*/
    struct {
        uint16_t lb, ub;
    } dport;
    uint8_t tcam_dport_count;
    uint16_t (*tcam_dport_prefix)[MAX_PFX_WC_ARRAY_LEN];
    uint16_t (*tcam_dport_wcard)[MAX_PFX_WC_ARRAY_LEN];


    uint64_t hit_count;
    uint32_t tcam_total_count; /* No of TCAM entries installed in TCAM */

} acl_entry_t;


typedef struct access_list_ {

    mtrie_t *mtrie;

} access_list_t;

access_list_t *
access_list_lib_create (const char **acl_entry_list,  int n_acl_entries) ;

acl_entry_t *
acl_entry_lib_rule_str_parse (const char *acl_entry_rule_str);

void 
acl_entry_free (acl_entry_t *acl_entry);

void 
acl_compile (acl_entry_t *acl_entry);

void 
acl_entry_install (access_list_t *access_list, acl_entry_t *acl_entry);

#endif 
