#include "../testsuitesupport/std_testcase.h"

#define DEST_SIZE 10

void bad_gets(void)
{
    char dest[DEST_SIZE];
    char *result;
    /* FLAW: gets() is inherently dangerous — no bounds checking,
       any input longer than dest causes a buffer overflow */
    result = gets(dest);
    if (result == NULL) { exit(1); }
    dest[DEST_SIZE - 1] = '\0';
    printLine(dest);
}
