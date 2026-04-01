#include "../testsuitesupport/std_testcase.h"

void smell_char_no_guard(void)
{
    char *data;

    /* SMELL: assigned non-NULL but no guard before data[0] */
    data = "Good";

    printHexCharLine(data[0]);
}