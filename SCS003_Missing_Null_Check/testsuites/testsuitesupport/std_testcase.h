/* Shared support header for CWE476 test cases */
#ifndef STD_TESTCASE_H
#define STD_TESTCASE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Shared struct used across all test cases */
typedef struct {
    int intOne;
    int intTwo;
} twoIntsStruct;

/* Output helpers */
void printLine(const char *line) {
    if (line != NULL) { printf("%s\n", line); }
}

void printHexCharLine(char c) {
    printf("%02x\n", (unsigned char)c);
}

#endif /* STD_TESTCASE_H */