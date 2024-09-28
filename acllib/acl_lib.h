#ifndef __ACL_LIB__
#define __ACL_LIB__

#include "acl_enums.h"

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
    uint32_t src_subnet_addr;
    uint32_t src_subnet_mask;

    /* Src Port*/
    struct {
        uint16_t lb, ub;
    } sport;

    /* Dest Address*/
    uint32_t dst_subnet_addr;
    uint32_t dst_subnet_mask;

    /* Dst Port*/
    struct {
        uint16_t lb, ub;
    } dport;

    uint64_t hit_count;
    uint32_t tcam_total_count; /* No of TCAM entries installed in TCAM */

} acl_entry_t;


typedef struct access_list_ {

    mtrie_t *mtrie;

} access_list_t;

#endif 
