#include "../testsuitesupport/std_testcase.h"

void bad_new_delete_struct(void)
{
    twoIntsStruct *data = new twoIntsStruct;
    data->intOne = 1;
    data->intTwo = 2;
    /* FLAW: delete data, then use bare pointer */
    delete data;
    printStructLine(data);
}
