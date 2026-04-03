#include "../testsuitesupport/std_testcase.h"

static char *helperBad(void)
{
    char *data = (char *)malloc(100);
    if (data == NULL) { return NULL; }
    memset(data, 'A', 99);
    data[99] = '\0';
    /* FLAW: free data then return the dangling pointer */
    free(data);
    return data;
}

void bad_return_freed_ptr(void)
{
    char *data = helperBad();
    printLine(data);
}
