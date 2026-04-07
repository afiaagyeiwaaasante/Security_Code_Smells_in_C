/* SCS008 CWE-134 — Missing Format Specifier
 * Group: fprintf_direct  |  Flow: 01 Baseline
 * BadSource: file read (fgets from FILE*)
 * GoodSink : fprintf(stderr, "%s\n", data) — literal format string
 * FIX: use a literal format specifier
 */
#include <stdio.h>
#include <string.h>

void good_fprintf_direct_01(void)
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
    /* FIX: literal format string */
    fprintf(stderr, "%s\n", data);
}

int main(void) { good_fprintf_direct_01(); return 0; }
