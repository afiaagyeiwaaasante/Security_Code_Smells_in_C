#include "../testsuitesupport/std_testcase.h"

void badSource(TwoIntsClass * &data)
{
    data = new TwoIntsClass;
    data->intOne = 1;
    data->intTwo = 2;
    /* FLAW: scalar delete via reference — caller's pointer becomes dangling */
    delete data;
}
