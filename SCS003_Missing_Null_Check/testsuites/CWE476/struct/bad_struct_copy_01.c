/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : struct — NULL propagation via local copy (variant 31)
 * Smell    : NULL assigned to data, copied to dataCopy, dereferenced via copy
 * Detector : detect_missing_guard (partial — warning only)
 * Expected : error [nullPointer] — detected as warning [missingNullCheck]
 *
 * Limitation:
 *   detect_null_deref misses this — it tracks the original variable (data)
 *   and does not follow the copy into dataCopy. detect_missing_guard does
 *   fire on dataCopy->intOne (unguarded dereference) but classifies it as
 *   warning rather than error since it has no NULL assignment evidence.
 */

#include "../testsuitesupport/std_testcase.h"

void bad_struct_copy(void)
{
    twoIntsStruct *data = NULL;

    /* NULL propagates through a local copy */
    twoIntsStruct *dataCopy = data;

    /* FLAW: dataCopy is NULL (copied from data), dereferenced without guard */
    printIntLine(dataCopy->intOne);
}
