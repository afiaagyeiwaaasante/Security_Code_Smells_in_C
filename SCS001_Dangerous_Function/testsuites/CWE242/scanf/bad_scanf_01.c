#include "../../testsuitesupport/std_testcase.h"

#define BUF_SIZE 10

void bad_scanf(void)
{
    char buf[BUF_SIZE];
    /* FLAW: scanf() with the bare %s specifier reads characters from stdin
       until whitespace with no length limit. Any input longer than BUF_SIZE-1
       overflows buf (CWE-242, CWE-120).
       The %s format specifier without an explicit field width is inherently
       dangerous — equivalent in risk to gets(). */
    scanf("%s", buf);
    printLine(buf);
}