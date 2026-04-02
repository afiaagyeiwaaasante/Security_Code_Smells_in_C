#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>
#include <stdint.h>

void good_use_after_free_int64(void)
{
    int64_t *data = (int64_t *)malloc(sizeof(int64_t));
    if (data == NULL) { return; }
    *data = 5;
    /* FIX: use data before freeing it */
    printInt64PtrLine(data);
    free(data);
}
