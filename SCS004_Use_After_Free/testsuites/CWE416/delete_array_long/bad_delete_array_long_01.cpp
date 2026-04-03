#include "../testsuitesupport/std_testcase.h"

void bad_delete_array_long(void)
{
    long *data = new long[10];
    data[0] = 5L;
    /* FLAW: delete[] data, then use it */
    delete[] data;
    printLongPtrLine(data);
}
