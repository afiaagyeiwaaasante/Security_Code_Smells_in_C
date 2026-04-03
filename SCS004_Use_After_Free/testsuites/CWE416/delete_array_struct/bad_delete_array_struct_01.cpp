#include "../testsuitesupport/std_testcase.h"

void bad_delete_array_struct(void)
{
    twoIntsStruct *data = new twoIntsStruct[10];
    data[0].intOne = 1;
    data[0].intTwo = 2;
    /* FLAW: delete[] data, then use it via &data[0] */
    delete[] data;
    printStructLine(&data[0]);
}
