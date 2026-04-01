/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : char — good (clean)
 * Fix      : null guard present before array index dereference
 * Detector : Detector 3 and 4
 * Expected : no detection
 */
#include "../testsuitesupport/std_testcase.h"

void good_char_guarded(void)
{
    char *data = NULL;

    /* FIX: guard present before data[0] */
    if (data != NULL)
    {
        printHexCharLine(data[0]);
    }
}