#include <assert.h>
#include <memory.h>
#include <arpa/inet.h>
#include "acl_lib_util.h"
#include "acl_enums.h" 

uint8_t
tcpip_protocol_classification(uint16_t proto) {

    switch(proto) {

        case ACL_IP:
            return NETWORK_LAYER;
        case ACL_ICMP:
            return APPLICATION_LAYER;
        case ACL_TCP:
        case ACL_UDP:
            return TRANSPORT_LAYER;
        default:
            return 0;
    }
}


typedef struct {
    int count;
    uint16_t (*data)[MAX_PFX_WC_ARRAY_LEN];
    uint16_t (*mask)[MAX_PFX_WC_ARRAY_LEN];
} acl_port_range_masks_t;

typedef struct {
    uint16_t lb;
    uint16_t ub;
} acl_port_range_t;

static int
range2mask_rec(acl_port_range_masks_t *masks, 
                            acl_port_range_t range,
                            uint16_t prefix, 
                            uint16_t mask, 
                            int b)
{
    int ret;

    if ( prefix >= range.lb && (prefix | mask) <= range.ub ) {
        if ( masks->count >= MAX_PFX_WC_ARRAY_LEN ) {
            assert(0);
        }
        (*(masks->data))[masks->count] = htons(prefix);
        (*(masks->mask))[masks->count] = htons(mask);
        masks->count++;
        return 0;
    } else if ( (prefix | mask) < range.lb || prefix > range.ub ) {
        return 0;
    } else {
        /* Partial */
    }
    if ( !mask ) {
        /* End of the recursion */
        return 0;
    }

    mask >>= 1;
    /* Left */
    ret = range2mask_rec(masks, range, prefix, mask, b + 1);
    if ( ret < 0 ) {
        return ret;
    }
    /* Right */
    prefix |= (1 << (15 - b));
    ret = range2mask_rec(masks, range, prefix, mask, b + 1);
    if ( ret < 0 ) {
        return ret;
    }
    return 0;
}

static int
range2mask (acl_port_range_masks_t *masks, acl_port_range_t range)
{   
    int b;
    uint16_t x;
    uint16_t y;
    uint16_t prefix;
    uint16_t mask;

    masks->count = 0;
    for ( b = 0; b < 16; b++ ) {
        x = range.lb & (1 << (15 - b));
        y = range.ub & (1 << (15 - b));
        if ( x != y ) {
            /* The most significant different bit */
            break;
        }
    }
    if (b == 0) {
        mask = 0xFFFF;
    }
    else {
        mask = (1 << (16 - b)) - 1;
    }
    prefix = range.lb & ~mask;

    return range2mask_rec(masks, range, prefix, mask, b);
}

void
range2_prefix_wildcard_conversion (uint16_t lb,  /* Input Lower bound */
                                                            uint16_t ub, /* Input Upper Bound */
                                                            uint16_t (*prefix)[MAX_PFX_WC_ARRAY_LEN],      /* Array of Prefix , Caller need to provide memory */
                                                            uint16_t (*wildcard)[MAX_PFX_WC_ARRAY_LEN],  /* Array of Prefix , Caller need to provide memory */
                                                            int *n) {

    acl_port_range_t range;
    acl_port_range_masks_t masks;

    range.lb = lb;
    range.ub = ub;

    memset (&masks, 0, sizeof(masks));
    
    masks.data = prefix;
    masks.mask = wildcard;

    range2mask (&masks, range);
    *n = masks.count;
}