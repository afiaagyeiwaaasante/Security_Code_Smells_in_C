/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : struct — NULL propagation via union field (variant 34)
 * Smell    : NULL assigned to one union member, read back via another, dereferenced
 * Detector : detect_missing_guard (partial — warning only)
 * Expected : error [nullPointer] — detected as warning [missingNullCheck]
 *
 * Limitation:
 *   detect_null_deref misses this — it has no model of union aliasing so
 *   cannot connect NULL in unionFirst to the dereference via unionSecond /
 *   retrieved. detect_missing_guard fires on retrieved->intOne (unguarded
 *   dereference) but classifies it as warning, not error.
 */

#include "../testsuitesupport/std_testcase.h"

typedef union
{
    twoIntsStruct *unionFirst;
    twoIntsStruct *unionSecond;
} structUnionType;

void bad_struct_union(void)
{
    twoIntsStruct *data = NULL;
    structUnionType myUnion;

    /* NULL flows into union */
    myUnion.unionFirst = data;

    /* Retrieved via the other union member — still NULL */
    twoIntsStruct *retrieved = myUnion.unionSecond;

    /* FLAW: retrieved is NULL, dereferenced without guard */
    printIntLine(retrieved->intOne);
}
