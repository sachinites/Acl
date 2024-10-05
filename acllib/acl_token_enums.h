#ifndef __ACL_TOKENS__
#define __ACL_TOKENS__

typedef enum acl_tokens_code {

	/* Operators */
	ACL_E_LESS_THAN,
	ACL_E_GR_THAN,
	ACL_E_EQ,

	/* Formats */
	ACL_E_WORD,
	ACL_E_INTEGER,
	ACL_E_IPV4_ADDR,
	ACL_E_STRING

} acl_tokens_code_t;


#endif 

