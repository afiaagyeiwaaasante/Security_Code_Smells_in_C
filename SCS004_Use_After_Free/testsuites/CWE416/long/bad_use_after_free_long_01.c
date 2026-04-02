#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>

void bad_use_after_free_long(void)
{
    long *data = (long *)malloc(sizeof(long));
    if (data == NULL) { return; }
    *data = 5;
    /* FLAW: free data, then use it */
    free(data);
    printLongPtrLine(data);
}
