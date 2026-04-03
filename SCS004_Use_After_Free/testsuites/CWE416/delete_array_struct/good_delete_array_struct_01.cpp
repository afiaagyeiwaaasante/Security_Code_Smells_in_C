#include "../testsuitesupport/std_testcase.h"

void good_delete_array_struct(void)
{
    twoIntsStruct *data = new twoIntsStruct[10];
    data[0].intOne = 1;
    data[0].intTwo = 2;
    /* FIX: use data before deleting it */
    printStructLine(&data[0]);
    delete[] data;
}
