#include "../testsuitesupport/std_testcase.h"

void good_new_delete_long(void)
{
    long *data = new long;
    *data = 5L;
    /* FIX: use data before deleting it */
    printLongLine(*data);
    delete data;
}
