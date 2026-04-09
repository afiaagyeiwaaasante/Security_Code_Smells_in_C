#include "../testsuitesupport/std_testcase.h"

#define DEST_SIZE 20

/* FLAW 1: gets() in first function — no bounds checking on name input */
void bad_read_name(void)
{
    char name[DEST_SIZE];
    gets(name);
    printLine(name);
}

/* FLAW 2: gets() in second function — no bounds checking on city input */
void bad_read_city(void)
{
    char city[DEST_SIZE];
    gets(city);
    printLine(city);
}

/* FLAW 3: gets() in third function — no bounds checking on country input */
void bad_read_country(void)
{
    char country[DEST_SIZE];
    gets(country);
    printLine(country);
}

/* Expected SmellDetect findings: 3
   Each function independently calls gets() — all three must be reported. */
