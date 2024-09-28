#include <stdint.h> 
#include "acl_enums.h"

uint8_t
tcpip_protocol_classification(uint16_t proto) ;

void
range2_prefix_wildcard_conversion (uint16_t lb,  /* Input Lower bound */
                                                            uint16_t ub, /* Input Upper Bound */
                                                            uint16_t (*prefix)[MAX_PFX_WC_ARRAY_LEN],      /* Array of Prefix , Caller need to provide memory */
                                                            uint16_t (*wildcard)[MAX_PFX_WC_ARRAY_LEN],  /* Array of Prefix , Caller need to provide memory */
                                                            int *n);