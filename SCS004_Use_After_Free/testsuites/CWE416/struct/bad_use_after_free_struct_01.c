#include "../testsuitesupport/std_testcase.h"

void bad_use_after_free_struct(void)
{
    twoIntsStruct *data = (twoIntsStruct *)malloc(100 * sizeof(twoIntsStruct));
    if (data == NULL) { return; }
    data[0].intOne = 1;
    data[0].intTwo = 2;
    /* FLAW: free data then use it via array-index argument */
    free(data);
    printStructLine(&data[0]);
}
