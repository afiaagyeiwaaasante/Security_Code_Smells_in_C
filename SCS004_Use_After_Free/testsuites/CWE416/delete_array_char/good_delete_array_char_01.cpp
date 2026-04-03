#include "../testsuitesupport/std_testcase.h"
#include <string.h>

void good_delete_array_char(void)
{
    char *data = new char[100];
    memset(data, 'A', 99);
    data[99] = '\0';
    /* FIX: use data before deleting it */
    printLine(data);
    delete[] data;
}
