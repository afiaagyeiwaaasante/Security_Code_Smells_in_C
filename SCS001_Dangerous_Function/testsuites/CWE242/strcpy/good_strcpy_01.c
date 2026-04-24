#include "../../testsuitesupport/std_testcase.h"

#define DEST_SIZE 10
#define SRC_SIZE  100

void good_strcpy(void)
{
    char dest[DEST_SIZE];
    char src[SRC_SIZE];
    /* FIX: strncpy() limits the copy to DEST_SIZE-1 characters.
       The explicit null terminator write ensures the buffer is always
       terminated regardless of src length. */
    strncpy(dest, src, DEST_SIZE - 1);
    dest[DEST_SIZE - 1] = '\0';
    printLine(dest);
}