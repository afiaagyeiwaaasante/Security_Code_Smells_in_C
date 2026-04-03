#include "../testsuitesupport/std_testcase.h"

void bad_new_delete_class(void)
{
    TwoIntsClass *data = new TwoIntsClass;
    data->intOne = 1;
    data->intTwo = 2;
    /* FLAW: delete data, then access member via arrow */
    delete data;
    printIntLine(data->intOne);
}
