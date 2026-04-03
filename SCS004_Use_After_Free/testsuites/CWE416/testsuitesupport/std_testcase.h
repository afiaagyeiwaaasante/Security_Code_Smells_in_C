/* Shared support header for CWE476 test cases */
#ifndef STD_TESTCASE_H
#define STD_TESTCASE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>

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

void printWCharPtrLine(wchar_t *data) {
    if (data != NULL) { wprintf(L"%ls\n", data); }
}

void printStructLine(const twoIntsStruct *s) {
    if (s != NULL) { printf("%d %d\n", s->intOne, s->intTwo); }
}

/* Value-accepting helpers — used to demonstrate use-after-free
   via dereferenced pointer: delete ptr; printIntLine(*ptr) */
void printIntLine(int val)           { printf("%d\n", val); }
void printLongLongLine(long long val){ printf("%lld\n", val); }
void printLongLine(long val)         { printf("%ld\n", val); }
void printWcharLine(wchar_t val)     { wprintf(L"%lc\n", val); }

/* C++ class used by new_delete_class test cases */
#ifdef __cplusplus
class TwoIntsClass {
public:
    int intOne;
    int intTwo;
    TwoIntsClass() : intOne(0), intTwo(0) {}
};
#endif

#endif /* STD_TESTCASE_H */