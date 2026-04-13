#include "../testsuitesupport/std_testcase.h"

/* GOOD: size is read from stdin but calloc is used instead of malloc,
 * which handles the count * size overflow check internally.
 * Flow variant: single function, fgets data source. */
void good_malloc_fgets(void)
{
    char buf[32];
    int data = -1;
    if (fgets(buf, sizeof(buf), stdin) != NULL)
    {
        data = atoi(buf);
    }
    int *p = (int *)calloc((size_t)data, sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
