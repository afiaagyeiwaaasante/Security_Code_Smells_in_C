#include "../testsuitesupport/std_testcase.h"

void bad_new_delete_long(void)
{
    long *data = new long;
    *data = 5L;
    /* FLAW: delete data, then dereference it */
    delete data;
    printLongLine(*data);
}
