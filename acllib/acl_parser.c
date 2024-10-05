#include <stdbool.h>
#include <stdlib.h>
#include "acl_lib.h"

/* CFG (Context Free Grammar ) to parse ACLs 

    ACL                    -> access-list <string> <int> ACTION PROTOCOL  SRC_INFO DST_INFO | $
    ACTION             -> permit | deny
    PROTOCOL       -> ip | tcp | udp | icmp
    SRC_INFO         -> ADDR  $ | OPERATORS <int> | range <int> <int>
    ADDR                 -> host <ipv4-addr> | <ipv4-addr> <ipv4-addr> | object-network <string>
    OPERATORS     -> eq | lt | gt 
    DST_INFO         -> ADDR  $ | range <int > <int> | OPERATORS <int>

*/

/* It is a separate project to learn how to parse complicated string using
    GNU lexical parser such as LEX*/
acl_entry_t * 
acl_entry_lib_rule_str_parse (const char *acl_entry_rule_str) {

    return NULL;
}