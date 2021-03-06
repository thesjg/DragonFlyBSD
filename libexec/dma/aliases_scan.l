%{

#include <string.h>
#include "aliases_parse.h"

#define YY_NO_INPUT

int yylex(void);
%}

%option yylineno
%option nounput

%%

[^:,#[:space:][:cntrl:]]+	{yylval.ident = strdup(yytext); return T_IDENT;}
[:,\n]				return yytext[0];
^([[:blank:]]*(#.*)?\n)+	;/* ignore empty lines */
(\n?[[:blank:]]+|#.*)+		;/* ignore whitespace and continuation */
\\\n				;/* ignore continuation.  not allowed in comments */
.				return T_ERROR;
<<EOF>>				return T_EOF;

%%
