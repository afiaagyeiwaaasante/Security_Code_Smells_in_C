#include "../testsuitesupport/std_testcase.h"

void good_delete_array_long(void)
{
    long *data = new long[10];
    data[0] = 5L;
    /* FIX: use data before deleting it */
    printLongPtrLine(data);
    delete[] data;
}
