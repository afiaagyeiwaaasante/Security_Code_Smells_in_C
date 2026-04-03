#include "../testsuitesupport/std_testcase.h"
#include <string.h>

void bad_delete_array_char(void)
{
    char *data = new char[100];
    memset(data, 'A', 99);
    data[99] = '\0';
    /* FLAW: delete[] data, then use it */
    delete[] data;
    printLine(data);
}
