#include "../testsuitesupport/std_testcase.h"

void bad_malloc(int n)
{
    int *p;
    /* FLAW: n * sizeof(int) may integer-overflow to a small value if n is large,
       causing malloc to allocate far less memory than intended */
    p = (int *)malloc(n * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
