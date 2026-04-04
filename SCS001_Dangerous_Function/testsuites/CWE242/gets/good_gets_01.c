#include "../testsuitesupport/std_testcase.h"

#define DEST_SIZE 10

void good_gets(void)
{
    char dest[DEST_SIZE];
    char *result;
    /* FIX: fgets() reads at most DEST_SIZE-1 characters — bounded and safe */
    result = fgets(dest, DEST_SIZE, stdin);
    if (result == NULL) { exit(1); }
    dest[DEST_SIZE - 1] = '\0';
    printLine(dest);
}
