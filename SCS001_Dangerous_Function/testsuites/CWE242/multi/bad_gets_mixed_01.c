#include "../testsuitesupport/std_testcase.h"

#define DEST_SIZE 20

/* FLAW: this function uses gets() — must be reported */
void bad_read_input(void)
{
    char buf[DEST_SIZE];
    gets(buf);
    printLine(buf);
}

/* FIX: this function uses fgets() with an explicit size — must NOT be reported */
void good_read_input(void)
{
    char buf[DEST_SIZE];
    fgets(buf, DEST_SIZE, stdin);
    printLine(buf);
}

/* Expected SmellDetect findings: 1
   Only bad_read_input() contains gets() — good_read_input() must be suppressed. */
