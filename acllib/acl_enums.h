#ifndef __ACL_ENUMS__
#define __ACL_ENUMS__

typedef enum {
    ACL_PERMIT,
    ACL_DENY,
} acl_action_t;

typedef enum {
    ACL_IP = 0x0800,
    ACL_ICMP = 1, 
    ACL_TCP = 6,
    ACL_UDP = 17,
    ACL_PROTO_NONE = 0xFFFF
} acl_proto_t;


#endif 