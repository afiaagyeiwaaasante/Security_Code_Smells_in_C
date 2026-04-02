#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>
#include <string.h>

void good_use_after_free_char(void)
{
    char *data = (char *)malloc(100 * sizeof(char));
    if (data == NULL) { return; }
    memset(data, 'A', 99);
    data[99] = '\0';
    /* FIX: use data before freeing it */
    printLine(data);
    free(data);
}
