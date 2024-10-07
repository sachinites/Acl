#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include <assert.h>
#include "../mtrie/mtrie.h"
#include "acl_lib.h"
#include "acl_lib_util.h" 

static void 
access_list_mtrie_free_app_data (mtrie_node_t *mnode) {
   
    acl_entry_t *temp;
    acl_entry_t *acl_entry = (acl_entry_t *)mnode->data;

    if (!mnode->data) return;

    while (acl_entry) {

        temp = acl_entry->mtrie_next;
        acl_entry->mtrie_prev = NULL;
        acl_entry->mtrie_next = NULL;
        acl_entry_dereference(acl_entry);
        acl_entry = temp;
    }

    mnode->data = NULL;
}

access_list_t *
access_list_lib_create (const char **acl_entry_list,  int n_acl_entries) {

    int i;
    acl_entry_t *acl_entry;
    const char *acl_entry_str;

    if (!n_acl_entries) return NULL;

    acl_entry_t **acl_entry_temp_array = (acl_entry_t **)calloc (n_acl_entries, sizeof (acl_entry_t *));

    for (i = 0; i < n_acl_entries; i++) {

        acl_entry_str = acl_entry_list[i];

        if ((acl_entry_temp_array[i] = acl_entry_lib_rule_str_parse (acl_entry_str))) {

            acl_entry_reference(acl_entry_temp_array[i]);

            printf ("Error : %s : Failed to Parse acl_entry \n   %s\n", 
                __FUNCTION__, acl_entry_str);
            i--;
            while (i >= 0) {
                acl_entry_dereference (acl_entry_temp_array[i]);
                i--;
            }
            free (acl_entry_temp_array);
            return NULL;
        }
    }

    access_list_t *access_list = (access_list_t *)calloc(1, sizeof (access_list_t));
    access_list->mtrie = (mtrie_t *)calloc(1, sizeof (mtrie_t));
    init_mtrie(access_list->mtrie, ACL_PREFIX_LEN, access_list_mtrie_free_app_data );

    for (i = 0; i < n_acl_entries; i++) {

        acl_compile (acl_entry_temp_array[i]);
        acl_entry_install (access_list, acl_entry_temp_array[i]);
        acl_entry_dereference (acl_entry_temp_array[i]);
        acl_entry_temp_array[i] = NULL;
    }

    free (acl_entry_temp_array);
    return access_list;
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


uint32_t 
acl_entry_get_total_tcam_count (acl_entry_t *acl_entry ) {

    uint32_t tcam_count = 
        acl_entry->tcam_sport_count * acl_entry->tcam_dport_count;

    return tcam_count;
}

static void
access_list_mtrie_allocate_mnode_data (mtrie_node_t *mnode, acl_entry_t *new_acl_entry ) {

    assert(!mnode->data);
    assert(new_acl_entry);

    if (mnode->data == NULL) {
        mnode->data = (void *)new_acl_entry;
        return;
    }

    acl_entry_t *old_head = (acl_entry_t *)mnode->data;
    new_acl_entry->mtrie_next = old_head;
    old_head->mtrie_prev = new_acl_entry;
    mnode->data = (void *)new_acl_entry;
    acl_entry_reference (new_acl_entry);
}

void 
acl_entry_install (access_list_t *access_list, acl_entry_t *acl_entry) {

    acl_entry->tcam_total_count = 
        acl_entry_get_total_tcam_count (acl_entry);

    if (!acl_entry->tcam_total_count) return;

    int src_port_it;
    int dst_port_it; 
    bitmap_t tcam_mask;
    bitmap_t tcam_prefix;
    int total_tcam_count = 0;
    bitmap_init(&tcam_prefix, ACL_PREFIX_LEN);
    bitmap_init(&tcam_mask, ACL_PREFIX_LEN);

    for (src_port_it = 0; src_port_it < acl_entry->tcam_sport_count; src_port_it++) {

        for (dst_port_it = 0;  dst_port_it < acl_entry->tcam_dport_count; dst_port_it++) {

            uint16_t *prefix_ptr2 = (uint16_t *)&tcam_prefix.bits;
            uint32_t *prefix_ptr4 = (uint32_t *)&tcam_prefix.bits;
            uint16_t *mask_ptr2 = (uint16_t *)&tcam_mask.bits;
            uint32_t *mask_ptr4 = (uint32_t *)&tcam_mask.bits;
            uint16_t bytes_copied = 0;

            /* L4 Protocol */
            memcpy(prefix_ptr2, &acl_entry->tcam_l4proto_prefix, sizeof(*prefix_ptr2));
            memcpy(mask_ptr2, &acl_entry->tcam_l4proto_wcard, sizeof(*mask_ptr2));
            prefix_ptr2++;
            mask_ptr2++;
            prefix_ptr4 = (uint32_t *)prefix_ptr2;
            mask_ptr4 = (uint32_t *)mask_ptr2;
            bytes_copied += sizeof(*prefix_ptr2);

            /* L3 Protocol*/
            memcpy(prefix_ptr2, &acl_entry->tcam_l3proto_prefix, sizeof(*prefix_ptr2));
            memcpy(mask_ptr2, &acl_entry->tcam_l3proto_wcard, sizeof(*mask_ptr2));
            prefix_ptr2++;
            mask_ptr2++;
            prefix_ptr4 = (uint32_t *)prefix_ptr2;
            mask_ptr4 = (uint32_t *)mask_ptr2;
            bytes_copied += sizeof(*prefix_ptr2);

            /* Src ip Address & Mask */
            memcpy(prefix_ptr4, &acl_entry->tcam_src_addr_prefix, sizeof(*prefix_ptr4));
            memcpy(mask_ptr4, &acl_entry->tcam_src_subnet_mask_prefix, sizeof(*mask_ptr4));
            prefix_ptr4++;
            mask_ptr4++;
            prefix_ptr2 = (uint16_t *)prefix_ptr4;
            mask_ptr2 = (uint16_t *)mask_ptr4;
            bytes_copied += sizeof(*prefix_ptr4);

            /* Src Port */
            memcpy(prefix_ptr2, &((*acl_entry->tcam_sport_prefix)[src_port_it]), sizeof(*prefix_ptr2));
            memcpy(mask_ptr2, &((*acl_entry->tcam_sport_wcard)[src_port_it]), sizeof(*mask_ptr2));
            prefix_ptr2++;
            mask_ptr2++;
            prefix_ptr4 = (uint32_t *)prefix_ptr2;
            mask_ptr4 = (uint32_t *)mask_ptr2;
            bytes_copied += sizeof(*prefix_ptr2);

            /* Dst ip Address & Mask */
            memcpy(prefix_ptr4, &acl_entry->tcam_dst_addr_prefix, sizeof(*prefix_ptr4));
            memcpy(mask_ptr4, &acl_entry->tcam_dst_subnet_mask_prefix, sizeof(*mask_ptr4));
            prefix_ptr4++;
            mask_ptr4++;
            prefix_ptr2 = (uint16_t *)prefix_ptr4;
            mask_ptr2 = (uint16_t *)mask_ptr4;
            bytes_copied += sizeof(*prefix_ptr4);

            /* Dst Port */
            memcpy(prefix_ptr2, &((*acl_entry->tcam_dport_prefix)[dst_port_it]), sizeof(*prefix_ptr2));
            memcpy(mask_ptr2, &((*acl_entry->tcam_dport_wcard)[dst_port_it]), sizeof(*mask_ptr2));
            prefix_ptr2++;
            mask_ptr2++;
            prefix_ptr4 = (uint32_t *)prefix_ptr2;
            mask_ptr4 = (uint32_t *)mask_ptr2;
            bytes_copied += sizeof(*prefix_ptr2);

            total_tcam_count++;

            mtrie_node_t *mnode = NULL;
            mtrie_ops_result_code_t result = mtrie_insert_prefix(
                access_list->mtrie,
                &tcam_prefix,
                &tcam_mask,
                ACL_PREFIX_LEN,
                &mnode);

            switch (result)
            {
                case MTRIE_INSERT_SUCCESS:
                case MTRIE_INSERT_DUPLICATE:
                    access_list_mtrie_allocate_mnode_data(mnode, acl_entry);
                    break;
                case MTRIE_INSERT_FAILED:
                    assert(0);
            }
        }
    }

    assert(total_tcam_count == acl_entry->tcam_total_count);
    bitmap_free_internal(&tcam_prefix);
    bitmap_free_internal(&tcam_mask);
}

void 
access_list_lib_destroy (access_list_t *access_list) {

    mtrie_destroy (access_list->mtrie);
    free (access_list->mtrie);
    free (access_list);
}

bool 
access_list_lib_evaluate1 (access_list_t *access_list, char *ip_hdr) {

    uint32_t src_addr = *(uint32_t *) (ip_hdr + 12 );
    uint32_t dst_addr = *(uint32_t *) (ip_hdr + 16 );
    uint16_t protocol = *(uint16_t *) (ip_hdr + 9);
    uint8_t ip_hdr_len = *(uint8_t *) (ip_hdr + 1 );
    char *transport_hdr = ip_hdr + ip_hdr_len;
    switch (protocol) {
        case ACL_TCP:
        case ACL_UDP:
            {
                uint16_t src_port = *(uint16_t *)(transport_hdr);
                uint16_t dst_port = *(uint16_t *)(transport_hdr + 2);
                return access_list_lib_evaluate2 (access_list,
                                ACL_IP, 
                                protocol, 
                                src_addr, dst_addr, src_port, dst_port);
            }
            break;
            default:
                assert(0); // Non IPV4 packets not supported
    }
    return false;
}

static void
bitmap_fill_with_params(
        bitmap_t *bitmap,
        uint16_t l3proto,
        uint16_t l4proto,
        uint32_t src_addr,
        uint32_t dst_addr,
        uint16_t src_port,
        uint16_t dst_port) {

        uint16_t *ptr2 = (uint16_t *)(bitmap->bits);

        /* Transport Protocol 2 B*/
        *ptr2 = htons(l4proto);
        ptr2++;

        /* Network Layer Protocol 2 B*/
        *ptr2 = htons(l3proto);
        ptr2++;

        uint32_t *ptr4 = (uint32_t *)ptr2;
        *ptr4 = htonl(src_addr);
        ptr4++;

        ptr2 = (uint16_t *)ptr4;
        *ptr2 = htons(src_port);
        ptr2++;

        ptr4 = (uint32_t *)ptr2;

        *ptr4 = htonl(dst_addr);
        ptr4++;

        ptr2 = (uint16_t *)ptr4;
        *ptr2 = htons(dst_port);

        /* 128 bit ACL entry size is supported today */
}

bool 
access_list_lib_evaluate2 (access_list_t *access_list, 
                                    uint16_t l3proto,
                                    uint16_t l4roto,
                                    uint32_t src_addr,
                                    uint32_t dst_addr,
                                    uint16_t src_port,
                                    uint16_t dst_port) {

    bitmap_t input;
    acl_entry_t *acl_entry;
    mtrie_node_t *hit_mnode = NULL;

    bitmap_init (&input, ACL_PREFIX_LEN);

    bitmap_fill_with_params (&input, l3proto, l4roto, src_addr, dst_addr, src_port, dst_port);

    hit_mnode = mtrie_longest_prefix_match_search  (access_list->mtrie, &input);
    
    if (!hit_mnode) return false;

    acl_entry = (acl_entry_t *) (hit_mnode->data);
    acl_entry->hit_count++;
    bool rc =  (acl_entry->action == ACL_PERMIT) ? true : false;
    return rc;
}

uint32_t 
acl_entry_get_hit_count (acl_entry_t *acl_entry) {

    return acl_entry->hit_count;
}

void
acl_print (acl_entry_t *acl_entry) {

    char ip_addr[16];

    printf (" %s %s",
        acl_entry->action == ACL_PERMIT ? "permit" : "deny" , 
        acl_proto_str ( acl_entry->proto));

    switch (acl_entry->proto)
    {
    case ACL_UDP:
    case ACL_TCP:
        if (acl_entry->sport.lb == 0 && acl_entry->sport.ub == 0)
            break;
        else if (acl_entry->sport.lb == 0 && acl_entry->sport.ub < ACL_MAX_PORTNO)
            printf(" lt %d", acl_entry->sport.ub);
        else if (acl_entry->sport.lb > 0 && acl_entry->sport.ub == ACL_MAX_PORTNO)
            printf(" gt %d", acl_entry->sport.lb);
        else if (acl_entry->sport.lb == acl_entry->sport.ub)
            printf(" eq %d", acl_entry->sport.lb);
        else
            printf(" range %d %d", acl_entry->sport.lb, acl_entry->sport.ub);
        break;
    default:;
    }

    inet_ntop (AF_INET, &acl_entry->src_addr, ip_addr, 16);
    printf (" %s", ip_addr);

    inet_ntop (AF_INET, &acl_entry->dst_addr, ip_addr, 16);
    printf (" %s", ip_addr);

    switch (acl_entry->proto)
    {
    case ACL_UDP:
    case ACL_TCP:
        if (acl_entry->dport.lb == 0 && acl_entry->dport.ub == 0)
            break;
        else if (acl_entry->dport.lb == 0 && acl_entry->dport.ub < ACL_MAX_PORTNO)
            printf(" lt %d", acl_entry->dport.ub);
        else if (acl_entry->dport.lb > 0 && acl_entry->dport.ub == ACL_MAX_PORTNO)
            printf(" gt %d", acl_entry->dport.lb);
        else if (acl_entry->dport.lb == acl_entry->dport.ub)
            printf(" eq %d", acl_entry->dport.lb);
        else
            printf(" range %d %d", acl_entry->dport.lb, acl_entry->dport.ub);
        break;
    default:;
    }

    printf ("    (Hits[%u] Tcam-Count[T:%u, R:%u])",
                        acl_entry->hit_count,
                        acl_entry->tcam_total_count,
                        acl_entry->ref_count);
}

void 
acl_entry_reference (acl_entry_t *acl_entry) { acl_entry->ref_count++; }

static void 
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
acl_entry_dereference (acl_entry_t *acl_entry) {

    assert (acl_entry->ref_count);
    acl_entry->ref_count--;
    if (acl_entry->ref_count) return;
    assert (!acl_entry->acclst_next && !acl_entry->acclst_prev);
    assert (!acl_entry->mtrie_next && !acl_entry->mtrie_prev);
    acl_entry_free (acl_entry);
}