#include "../testsuitesupport/std_testcase.h"

void bad_double_free_char(void)
{
    char *data = (char *)malloc(100);
    if (data == NULL) { return; }
    memset(data, 'A', 99);
    data[99] = '\0';
    free(data);
    /* FLAW: free data a second time */
    free(data);
}
