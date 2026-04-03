#include "../testsuitesupport/std_testcase.h"

void good_new_delete_char(void)
{
    char *data = new char;
    *data = 'A';
    /* FIX: use data before deleting it */
    printHexCharLine(*data);
    delete data;
}
