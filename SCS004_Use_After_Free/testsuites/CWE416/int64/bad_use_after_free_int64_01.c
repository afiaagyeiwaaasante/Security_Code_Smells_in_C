#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>
#include <stdint.h>

void bad_use_after_free_int64(void)
{
    int64_t *data = (int64_t *)malloc(sizeof(int64_t));
    if (data == NULL) { return; }
    *data = 5;
    /* FLAW: free data, then use it */
    free(data);
    printInt64PtrLine(data);
}
