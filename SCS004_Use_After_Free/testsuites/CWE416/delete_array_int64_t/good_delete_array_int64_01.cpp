#include "../testsuitesupport/std_testcase.h"

void good_delete_array_int64(void)
{
    int64_t *data = new int64_t[10];
    data[0] = 5;
    /* FIX: use data before deleting it */
    printInt64PtrLine(data);
    delete[] data;
}
