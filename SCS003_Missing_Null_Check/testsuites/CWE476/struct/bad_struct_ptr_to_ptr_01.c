/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : struct — NULL propagation via pointer-to-pointer (variant 32)
 * Smell    : NULL written through **dataPtr, read back and dereferenced
 * Detector : detect_null_deref (KNOWN LIMITATION — false negative)
 * Expected : error [nullPointer] — NOT detected by current pipeline
 *
 * Why this is a limitation:
 *   The NULL is stored via *dataPtr = NULL and retrieved via data = *dataPtr.
 *   The detector does not model pointer indirection, so it cannot connect
 *   the write through dataPtr to the subsequent dereference of data.
 */

#include "../testsuitesupport/std_testcase.h"

void bad_struct_ptr_to_ptr(void)
{
    twoIntsStruct *data;
    twoIntsStruct **dataPtr = &data;

    /* FLAW: NULL written through pointer-to-pointer */
    *dataPtr = NULL;

    /* data is now NULL via indirection — dereferenced without guard */
    printIntLine(data->intOne);
}
