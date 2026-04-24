#include "../../testsuitesupport/std_testcase.h"

#define BUF_SIZE   20
#define SUFFIX_SIZE 30

void bad_strcat(void)
{
    char buf[BUF_SIZE] = "Hello";
    char suffix[SUFFIX_SIZE];
    /* FLAW: strcat() appends suffix to buf with no bounds check.
       If strlen(buf) + strlen(suffix) >= BUF_SIZE, the append overflows.
       No check is made against the remaining capacity of buf (CWE-242, CWE-120). */
    strcat(buf, suffix);
    printLine(buf);
}