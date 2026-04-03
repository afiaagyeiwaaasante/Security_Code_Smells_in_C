#include "../testsuitesupport/std_testcase.h"

void badSource(TwoIntsClass * &data);

void bad_interprocedural_new_delete_class(void)
{
    TwoIntsClass *data = NULL;
    badSource(data);
    /* FLAW: data was delete'd inside badSource, but member accessed here */
    printIntLine(data->intOne);
}
