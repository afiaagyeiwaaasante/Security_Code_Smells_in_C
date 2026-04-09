#include "../testsuitesupport/std_testcase.h"

void good_malloc(int n)
{
    int *p;
    /* FIX: calloc(count, size) checks for integer overflow internally
       and returns NULL if count * size would overflow */
    p = (int *)calloc((size_t)n, sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
