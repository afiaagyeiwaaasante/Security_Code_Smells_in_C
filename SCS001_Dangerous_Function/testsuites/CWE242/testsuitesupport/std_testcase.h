/* Shared support header for CWE242 test cases */
#ifndef STD_TESTCASE_H
#define STD_TESTCASE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printLine(const char *line) {
    if (line != NULL) { printf("%s\n", line); }
}

#endif /* STD_TESTCASE_H */
