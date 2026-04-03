#include "../testsuitesupport/std_testcase.h"

void badSource(char * &data);

void bad_interprocedural_new_delete_char(void)
{
    char *data = NULL;
    badSource(data);
    /* FLAW: data was delete'd inside badSource, but used here */
    printHexCharLine(*data);
}
