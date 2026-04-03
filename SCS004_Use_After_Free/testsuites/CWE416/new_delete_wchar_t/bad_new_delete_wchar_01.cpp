#include "../testsuitesupport/std_testcase.h"

void bad_new_delete_wchar(void)
{
    wchar_t *data = new wchar_t;
    *data = L'A';
    /* FLAW: delete data, then dereference it */
    delete data;
    printWcharLine(*data);
}
