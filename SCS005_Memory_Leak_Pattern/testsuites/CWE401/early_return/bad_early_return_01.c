/* CWE-401 Memory Leak — early return without free
 * FLAW: malloc() allocated, then function returns early on one path
 *       without freeing the memory first.
 */
#include <stdlib.h>

int bad_early_return(int n)
{
    int *data = (int *)malloc((size_t)n * sizeof(int));
    if (data == NULL) { return -1; }

    if (n < 0) {
        /* FLAW: data leaked — return without free */
        return -1;
    }

    data[0] = n;
    free(data);
    return 0;
}
