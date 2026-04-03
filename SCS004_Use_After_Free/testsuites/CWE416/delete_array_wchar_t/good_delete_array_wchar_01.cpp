#include "../testsuitesupport/std_testcase.h"

void good_delete_array_wchar(void)
{
    wchar_t *data = new wchar_t[100];
    data[0] = L'A';
    data[1] = L'\0';
    /* FIX: use data before deleting it */
    printWCharPtrLine(data);
    delete[] data;
}
