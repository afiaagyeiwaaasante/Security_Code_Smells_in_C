/* SCS008 CWE-134 — Missing Format Specifier
 * Group: fprintf_direct  |  Flow: 01 Baseline
 * BadSource: file read (fgets from FILE*)
 * BadSink  : fprintf(stderr, data) — variable as format argument
 * FLAW: user-controlled string from file used directly as fprintf format
 */
#include <stdio.h>
#include <string.h>

void bad_fprintf_direct_01(void)
{
    char data[100] = "";
    FILE *fp = fopen("input.txt", "r");
    if (fp != NULL) {
        if (fgets(data, sizeof(data), fp) != NULL) {
            size_t len = strlen(data);
            if (len > 0 && data[len - 1] == '\n') data[len - 1] = '\0';
        }
        fclose(fp);
    }
    /* FLAW: variable used as format argument to fprintf */
    fprintf(stderr, data);
}

int main(void) { bad_fprintf_direct_01(); return 0; }
