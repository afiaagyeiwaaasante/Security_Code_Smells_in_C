#include "../testsuitesupport/std_testcase.h"

void bad_new_delete_int64(void)
{
    int64_t *data = new int64_t;
    *data = 5LL;
    /* FLAW: delete data, then dereference it */
    delete data;
    printLongLongLine((long long)*data);
}
