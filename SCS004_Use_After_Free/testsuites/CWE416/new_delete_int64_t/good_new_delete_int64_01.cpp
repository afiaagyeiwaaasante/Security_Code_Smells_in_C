#include "../testsuitesupport/std_testcase.h"

void good_new_delete_int64(void)
{
    int64_t *data = new int64_t;
    *data = 5LL;
    /* FIX: use data before deleting it */
    printLongLongLine((long long)*data);
    delete data;
}
