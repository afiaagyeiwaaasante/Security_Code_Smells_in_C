#include "../testsuitesupport/std_testcase.h"

static char *helperGood(void)
{
    char *data = (char *)malloc(100);
    if (data == NULL) { return NULL; }
    memset(data, 'A', 99);
    data[99] = '\0';
    /* FIX: return data without freeing it first */
    return data;
}

void good_return_freed_ptr(void)
{
    char *data = helperGood();
    printLine(data);
    free(data);
}
