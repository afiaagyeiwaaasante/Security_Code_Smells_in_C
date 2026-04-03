#include "../testsuitesupport/std_testcase.h"

void good_double_free_char(void)
{
    char *data = (char *)malloc(100);
    if (data == NULL) { return; }
    memset(data, 'A', 99);
    data[99] = '\0';
    free(data);
    /* FIX: set to NULL after free — prevents double free */
    data = NULL;
}
