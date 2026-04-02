#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>

/* callee declaration */
void badSource(long *data);

void bad_interprocedural_uaf_long(void)
{
    long *data = (long *)malloc(sizeof(long));
    if (data == NULL) { return; }
    *data = 5;
    badSource(data);
    /* FLAW: use data after callee freed it */
    printLongPtrLine(data);
}
