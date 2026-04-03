#include "../testsuitesupport/std_testcase.h"

void badSource(char * &data)
{
    data = new char;
    *data = 'A';
    /* FLAW: scalar delete via reference — caller's pointer becomes dangling */
    delete data;
}
