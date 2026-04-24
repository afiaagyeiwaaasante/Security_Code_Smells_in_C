#include "../../testsuitesupport/std_testcase.h"

#define DEST_SIZE 10
#define SRC_SIZE  100

void bad_strcpy(void)
{
    char dest[DEST_SIZE];
    char src[SRC_SIZE];
    /* FLAW: strcpy() copies until the null terminator with no length limit.
       If src is longer than DEST_SIZE-1, dest overflows (CWE-242, CWE-120).
       The destination buffer size is never checked against the source length. */
    strcpy(dest, src);
    printLine(dest);
}