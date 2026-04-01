#include "../testsuitesupport/std_testcase.h"

void good_char_guarded(void)
{
    char *data;

    data = NULL;

    /* FIX: guard present before data[0] */
    if (data != NULL)
    {
        printHexCharLine(data[0]);
    }
}