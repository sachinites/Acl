%{

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "ParserExport.h"

char lex_buffer[MAX_STRING_SIZE] = {0};
char *curr_ptr = lex_buffer;
char *lex_curr_token;
int lex_curr_token_len;

stk_t undo_stack = {-1, {0, 0, 0}};

void 
lex_push(lex_data_t lex_data) {
    assert (undo_stack.top < MAX_MEXPR_LEN -1);
    undo_stack.data[++undo_stack.top] = lex_data;
    lex_curr_token = (char *)lex_data.token_val;
    lex_curr_token_len = lex_data.token_len;
}

lex_data_t
lex_pop() {
    assert (undo_stack.top > -1);
    lex_data_t res = undo_stack.data[undo_stack.top] ;
    undo_stack.top--;
    if (undo_stack.top > -1) {
        lex_data_t stck_top_lexd = undo_stack.data[undo_stack.top] ;
        lex_curr_token = (char *)stck_top_lexd.token_val;
        lex_curr_token_len = stck_top_lexd.token_len;
    }
    else {
        lex_curr_token = NULL;
        lex_curr_token_len = 0;
    }
    return res;
}

void 
yyrewind (int n) {

    if (n <= 0) return;
    if (curr_ptr == lex_buffer) return;
    int data_len = 0;
    lex_data_t lex_data;
    while (n)  {
        lex_data = lex_pop();
        data_len += lex_data.token_len;
        if (lex_data.token_code == PARSER_WHITE_SPACE) {
            continue;
        }
        n--;
        lex_data.token_code = 0;
        lex_data.token_len = 0;
        if (lex_data.token_val) {
            free (lex_data.token_val);
            lex_data.token_val = NULL;
        }
    }
    curr_ptr -= data_len;
    yy_scan_string(curr_ptr);
}

void
RESTORE_CHKP(int a) {

    lex_data_t lex_data;
    int data_len = 0;

    while (undo_stack.top > a) {
        
        lex_data =  lex_pop();
        data_len += lex_data.token_len;

        if (lex_data.token_val) { 
            free (lex_data.token_val);
            lex_data.token_val = NULL;
        }
    }
    curr_ptr -= data_len;
    yy_scan_string(curr_ptr);
}

unsigned char *
parser_alloc_token_value_default (uint16_t token_id) {

    unsigned char *ptr = (unsigned char *)(calloc (1, yyleng + 1));
    strncpy ((char *)ptr, (const char *)yytext, yyleng);
    ptr [yyleng] = '\0';
    return ptr;
}

int 
cyylex () {

    int token_code =  yylex();
    curr_ptr += yyleng;
    lex_data_t lex_data;
    lex_data.token_code = token_code;
    lex_data.token_len = yyleng;
    lex_data.token_val = parser_alloc_token_value_default  (token_code);
    lex_push(lex_data);
    return token_code;
}

void 
process_white_space(int n) {

    lex_data_t lex_data;
    curr_ptr += n;
    lex_data.token_code = PARSER_WHITE_SPACE;
    lex_data.token_len = n;
    lex_data.token_val = NULL;
    lex_push(lex_data);
}

int cyylexlh() {

    int token_code = cyylex();
    yyrewind(1);
    return token_code;
}

int cyylexlb() {

    yyrewind(1);
    int token_code = cyylex();
    yyrewind(1);
    return token_code;
}

void 
Parser_stack_reset () {

    int i;
    lex_data_t *lex_data;

    for (i = 0; i < undo_stack.top; i++) {
        lex_data = &undo_stack.data[i];
        lex_data->token_code = 0;
        lex_data->token_len = 0;
        if (lex_data->token_val) {
            free (lex_data->token_val);
            lex_data->token_val = NULL;
        }
    }
    undo_stack.top = -1;
    curr_ptr = lex_buffer;
}

int 
Parser_get_current_stack_index () {
    return undo_stack.top;
}

void 
lex_set_scan_buffer (const char *buffer) {

    yy_scan_string (buffer);
}

/* ========================================
            Warning : Do  Not Modify this file above this line 
    ======================================= */
            /* User specific parsing logic starts below */



/* User specific header files */
#include "acl_token_enums.h"


%}

%%

"lt" {
    return ACL_E_LESS_THAN;
}

"gt" {
    return ACL_E_GR_THAN;
}

"eq" {
    return ACL_E_EQ;
}

\n {
    return PARSER_EOL;
}

"\\\n" {

}

[ ] {
    /* Ignore */
    process_white_space(1);
}

[\t] {
    /*ignore*/
    process_white_space(4);
}

"\\q" {
    return PARSER_QUIT;
}

[a-zA-Z0-9]+ {
    return ACL_E_WORD;
}

0|-?[1-9][0-9]* {
    return ACL_E_INTEGER;
}

(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]) {

    return ACL_E_IPV4_ADDR;
}

[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+ {
    return ACL_E_STRING;
}

. {
    // ignore any other character
}

%%

#if 0
int 
main (int argc) {

    int token_code = cyylex();
    printf ("token_code = %d,  token = %s \n", token_code, yytext);
    return 0;
}
#endif
