%{
#include <stdio.h>
%}

%%
[0-9]+     { printf("NUMBER: %s\n", yytext); }
[a-zA-Z_][a-zA-Z0-9_]*   { printf("IDENTIFIER: %s\n", yytext); }
[\+\-\*/]   { printf("OPERATOR: %s\n", yytext); }
\n          { /* Ignore new lines */ }
.           { printf("UNKNOWN: %s\n", yytext); }
%%

int main() {
    yylex();
    return 0;
}

int yywrap() {
    return 1;
}
