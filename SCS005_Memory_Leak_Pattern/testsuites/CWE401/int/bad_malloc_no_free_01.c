/* CWE-401 Memory Leak — no free on exit
 * FLAW: malloc() called but free() never called before function returns.
 *       The allocated block is permanently leaked.
 */
#include <stdlib.h>

void bad_malloc_no_free(int n)
{
    int *data = (int *)malloc((size_t)n * sizeof(int));
    if (data == NULL) { return; }

    data[0] = 1;
    /* FLAW: data is never freed */
}
