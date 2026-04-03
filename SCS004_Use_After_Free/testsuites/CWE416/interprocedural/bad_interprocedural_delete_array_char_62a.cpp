#include "../testsuitesupport/std_testcase.h"

void badSource(char * &data);

void bad_interprocedural_delete_array_char(void)
{
    char *data = NULL;
    badSource(data);
    /* FLAW: data was delete[]'d inside badSource, but used here */
    printLine(data);
}
