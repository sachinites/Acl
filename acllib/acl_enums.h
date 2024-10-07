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
    ACL_PROTO_ANY = 0xFFFF

} acl_proto_t;

static char *
acl_proto_str (acl_proto_t proto) {

    switch (proto) {
        case ACL_IP:
            return "ip";
        case ACL_ICMP:
            return "icmp";
        case ACL_TCP:
            return "tcp";
        case ACL_UDP:
            return "udp";
        case ACL_PROTO_ANY:
            return "any";
        default:
            return "unknown";
    }
}

#define ACL_PREFIX_LEN  128
#define MAX_PFX_WC_ARRAY_LEN 64
#define ACL_MAX_PORTNO 65535 

#define APPLICATION_LAYER 5 
#define TRANSPORT_LAYER 4
#define NETWORK_LAYER 3 
#define DATA_LINK_LAYER 2
#define PHYSICAL_LAYER 1

#endif 