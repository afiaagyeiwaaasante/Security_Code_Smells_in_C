#include "../../testsuitesupport/std_testcase.h"

#define BUF_SIZE 10

/* FLAW: gets() is concealed inside a macro expansion.
   After preprocessing the dangerous call is present, but srcML parses the
   source text before macro expansion, so the call node name resolves to
   the macro name rather than "gets".
   Expected: SmellDetect MISSES this case (known limitation — macro-wrapped calls).
   Expected: cppcheck and Joern may or may not detect depending on whether
             they perform preprocessing before AST construction. */
#define READ_LINE(buf) gets(buf)

void bad_gets_macro(void)
{
    char dest[BUF_SIZE];
    char *result;
    result = READ_LINE(dest);
    if (result == NULL) { exit(1); }
    printLine(dest);
}