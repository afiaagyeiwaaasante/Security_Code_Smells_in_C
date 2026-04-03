#include "../testsuitesupport/std_testcase.h"

void good_new_delete_wchar(void)
{
    wchar_t *data = new wchar_t;
    *data = L'A';
    /* FIX: use data before deleting it */
    printWcharLine(*data);
    delete data;
}
