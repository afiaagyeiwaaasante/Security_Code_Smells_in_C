#include "../testsuitesupport/std_testcase.h"

void bad_new_delete_int(void)
{
    int *data = new int;
    *data = 5;
    /* FLAW: delete data, then dereference it */
    delete data;
    printIntLine(*data);
}
