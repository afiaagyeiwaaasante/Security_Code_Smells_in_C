#include "../testsuitesupport/std_testcase.h"

void bad_new_delete_char(void)
{
    char *data = new char;
    *data = 'A';
    /* FLAW: delete data, then dereference it */
    delete data;
    printHexCharLine(*data);
}
