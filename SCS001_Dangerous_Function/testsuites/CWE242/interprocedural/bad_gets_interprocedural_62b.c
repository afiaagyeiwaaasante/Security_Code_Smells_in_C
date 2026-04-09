#include "../testsuitesupport/std_testcase.h"

void read_input(char *dest)
{
    char *result;
    /* FLAW: gets() called on a buffer received from the caller —
       cross-file dangerous function use, invisible to single-file analysis */
    result = gets(dest);
    if (result == NULL) { exit(1); }
}
