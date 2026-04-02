#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>

void good_use_after_free_int(void)
{
    int *data = (int *)malloc(sizeof(int));
    if (data == NULL) { return; }
    *data = 5;
    /* FIX: use data before freeing it */
    printIntPtrLine(data);
    free(data);
}
