#include "../testsuitesupport/std_testcase.h"

void good_new_delete_struct(void)
{
    twoIntsStruct *data = new twoIntsStruct;
    data->intOne = 1;
    data->intTwo = 2;
    /* FIX: use data before deleting it */
    printStructLine(data);
    delete data;
}
