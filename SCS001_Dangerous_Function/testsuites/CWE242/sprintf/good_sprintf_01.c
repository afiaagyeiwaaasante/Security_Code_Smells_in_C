#include "../../testsuitesupport/std_testcase.h"

#define BUF_SIZE  20
#define DATA_SIZE 100

void good_sprintf(void)
{
    char buf[BUF_SIZE];
    char data[DATA_SIZE];
    /* FIX: snprintf() accepts an explicit size argument limiting the number
       of characters written (including the null terminator) to BUF_SIZE.
       Any overflow is truncated safely; buf is always null-terminated. */
    snprintf(buf, BUF_SIZE, "%s", data);
    printLine(buf);
}