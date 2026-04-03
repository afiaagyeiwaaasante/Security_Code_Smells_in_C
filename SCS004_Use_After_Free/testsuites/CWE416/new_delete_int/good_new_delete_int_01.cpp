#include "../testsuitesupport/std_testcase.h"

void good_new_delete_int(void)
{
    int *data = new int;
    *data = 5;
    /* FIX: use data before deleting it */
    printIntLine(*data);
    delete data;
}
