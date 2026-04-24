#include "../../testsuitesupport/std_testcase.h"

#define BUF_SIZE   10

void good_scanf(void)
{
    char buf[BUF_SIZE];
    /* FIX: the explicit field width in the format string limits the number
       of characters read to BUF_SIZE-1. scanf() appends the null terminator
       automatically, so buf is always safely bounded.
       The literal "%9s" is used directly so static analysis tools can inspect
       the format string without macro expansion. */
    scanf("%9s", buf);
    printLine(buf);
}