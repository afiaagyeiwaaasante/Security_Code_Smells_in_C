#include "../testsuitesupport/std_testcase.h"

/* Declaration of callee defined in bad_gets_interprocedural_62b.c */
void read_input(char *dest);

void bad_gets_interprocedural(void)
{
    char buf[10];
    /* FLAW: gets() is hidden inside read_input() in a separate file —
       a single-file analyser cannot see the dangerous call from here */
    read_input(buf);
    printLine(buf);
}
