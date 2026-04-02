#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>

void bad_use_after_free_int(void)
{
    int *data = (int *)malloc(sizeof(int));
    if (data == NULL) { return; }
    *data = 5;
    /* FLAW: free data, then use it */
    free(data);
    printIntPtrLine(data);
}
