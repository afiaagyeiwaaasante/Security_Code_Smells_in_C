#include "../../testsuitesupport/std_testcase.h"

#define BUF_SIZE  20
#define DATA_SIZE 100

void bad_sprintf(void)
{
    char buf[BUF_SIZE];
    char data[DATA_SIZE];
    /* FLAW: sprintf() writes the formatted result into buf with no output
       length limit. If the formatted string exceeds BUF_SIZE-1 characters,
       the write overflows buf (CWE-242, CWE-120).
       There is no mechanism to limit the number of characters written. */
    sprintf(buf, "%s", data);
    printLine(buf);
}