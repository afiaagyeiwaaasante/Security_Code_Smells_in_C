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

/* Pointer-accepting helpers — used to demonstrate use-after-free
   by passing the freed pointer directly as an argument */
void printIntPtrLine(int *data) {
    if (data != NULL) { printf("%d\n", *data); }
}

void printInt64PtrLine(int64_t *data) {
    if (data != NULL) { printf("%lld\n", (long long)*data); }
}

void printLongPtrLine(long *data) {
    if (data != NULL) { printf("%ld\n", *data); }
}

#endif /* STD_TESTCASE_H */