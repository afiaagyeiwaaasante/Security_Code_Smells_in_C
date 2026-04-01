/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : char — smell (warning level)
 * Sink     : array index dereference data[0], non-NULL assigned, no guard
 * Detector : Detector 4 (missing_guard) — array index query
 * Expected : warning [missingNullCheck] [missing_guard]
 *
 * This is a security code smell — data is currently valid but the
 * absence of a null guard makes it fragile. Any future change to
 * the data source that introduces NULL will cause a crash.
 */
#include "../testsuitesupport/std_testcase.h"

void smell_char_no_guard(void)
{
    char *data = "Good";

    /* SMELL: data is valid now but no null guard — fragile */
    printHexCharLine(data[0]);
}