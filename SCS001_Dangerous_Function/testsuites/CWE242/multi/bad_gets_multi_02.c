#include "../testsuitesupport/std_testcase.h"

#define DEST_SIZE 20

/* FLAW: gets() called twice within the same function —
   both calls must be reported as separate findings. */
void bad_read_both(void)
{
    char first[DEST_SIZE];
    char last[DEST_SIZE];
    /* FLAW 1: first gets() call */
    gets(first);
    /* FLAW 2: second gets() call */
    gets(last);
    printLine(first);
    printLine(last);
}

/* Expected SmellDetect findings: 2
   Both gets() calls in the same function must each produce a finding. */
