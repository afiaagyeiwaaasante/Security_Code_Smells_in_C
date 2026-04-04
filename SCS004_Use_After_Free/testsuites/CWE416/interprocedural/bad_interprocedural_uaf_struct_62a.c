#include "../testsuitesupport/std_testcase.h"

/* badSource: allocates, initialises, and frees the struct array.
   The caller will attempt to use data after this call returns. */
void bad_source_struct(twoIntsStruct **data);

void bad_use_after_free_struct_62(void)
{
    twoIntsStruct *data = NULL;
    bad_source_struct(&data);
    /* FLAW: data was freed inside bad_source_struct */
    printStructLine(&data[0]);
}
