#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>

/* FLAW: callee frees the pointer — caller will still use it */
void badSource(long *data)
{
    free(data);
}
