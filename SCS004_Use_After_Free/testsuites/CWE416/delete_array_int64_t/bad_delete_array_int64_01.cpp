#include "../testsuitesupport/std_testcase.h"

void bad_delete_array_int64(void)
{
    int64_t *data = new int64_t[10];
    data[0] = 5;
    /* FLAW: delete[] data, then use it */
    delete[] data;
    printInt64PtrLine(data);
}
