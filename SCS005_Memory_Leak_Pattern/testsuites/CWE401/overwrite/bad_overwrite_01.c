/* CWE-401 Memory Leak — pointer overwrite leak
 * FLAW: pointer is reassigned a new malloc() without freeing the
 *       first allocation.  The original block is permanently leaked.
 */
#include <stdlib.h>

void bad_overwrite(int n)
{
    int *data = (int *)malloc((size_t)n * sizeof(int));
    if (data == NULL) { return; }

    /* FLAW: first block leaked — overwritten without free */
    data = (int *)malloc((size_t)n * 2 * sizeof(int));
    if (data == NULL) { return; }

    data[0] = n;
    free(data);
}
