#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>

void good_use_after_free_long(void)
{
    long *data = (long *)malloc(sizeof(long));
    if (data == NULL) { return; }
    *data = 5;
    /* FIX: use data before freeing it */
    printLongPtrLine(data);
    free(data);
}
