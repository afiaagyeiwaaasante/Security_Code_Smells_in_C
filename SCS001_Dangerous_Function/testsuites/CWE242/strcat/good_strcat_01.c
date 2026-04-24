#include "../../testsuitesupport/std_testcase.h"

#define BUF_SIZE   20
#define SUFFIX_SIZE 30

void good_strcat(void)
{
    char buf[BUF_SIZE] = "Hello";
    char suffix[SUFFIX_SIZE];
    /* FIX: strncat() limits the append to the remaining capacity of buf.
       The expression (BUF_SIZE - strlen(buf) - 1) ensures the buffer
       cannot overflow regardless of suffix length. */
    strncat(buf, suffix, BUF_SIZE - strlen(buf) - 1);
    printLine(buf);
}