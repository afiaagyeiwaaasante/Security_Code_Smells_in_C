#include "../testsuitesupport/std_testcase.h"
#include <string.h>

void badSource(char * &data)
{
    data = new char[100];
    memset(data, 'A', 99);
    data[99] = '\0';
    /* FLAW: delete[] data via reference — caller's pointer becomes dangling */
    delete[] data;
}
