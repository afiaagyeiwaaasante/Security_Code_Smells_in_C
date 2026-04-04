#include "../testsuitesupport/std_testcase.h"

void good_use_after_free_struct(void)
{
    twoIntsStruct *data = (twoIntsStruct *)malloc(100 * sizeof(twoIntsStruct));
    if (data == NULL) { return; }
    data[0].intOne = 1;
    data[0].intTwo = 2;
    /* FIX: use data before freeing it */
    printStructLine(&data[0]);
    free(data);
}
