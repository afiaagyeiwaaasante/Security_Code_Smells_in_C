#include "../../testsuitesupport/std_testcase.h"

#define BUF_SIZE 10

/* FLAW: gets() is assigned to a function pointer and called indirectly.
   The call site's AST node name is the pointer variable ("reader"), not "gets".
   A name-based srcQL query therefore does not match this call site.
   Expected: SmellDetect MISSES this case (known limitation — function pointer alias).
   Expected: cppcheck likely MISSES this (name-based checker).
   Expected: Joern MAY detect this if CPG data flow resolves the pointer target,
             but this depends on Joern's alias analysis depth for C. */
void bad_gets_fnptr(void)
{
    char dest[BUF_SIZE];
    char *(*reader)(char *) = gets;   /* gets assigned to function pointer */
    char *result;
    result = reader(dest);            /* indirect call — not a direct gets() node */
    if (result == NULL) { exit(1); }
    printLine(dest);
}