#include "../testsuitesupport/std_testcase.h"

void bad_source_struct(twoIntsStruct **data)
{
    *data = (twoIntsStruct *)malloc(100 * sizeof(twoIntsStruct));
    if (*data == NULL) { return; }
    (*data)[0].intOne = 1;
    (*data)[0].intTwo = 2;
    /* FLAW: free data — caller will use it after this returns */
    free(*data);
}
