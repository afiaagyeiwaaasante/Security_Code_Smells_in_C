#include "../testsuitesupport/std_testcase.h"

void good_new_delete_class(void)
{
    TwoIntsClass *data = new TwoIntsClass;
    data->intOne = 1;
    data->intTwo = 2;
    /* FIX: use data before deleting it */
    printIntLine(data->intOne);
    delete data;
}
