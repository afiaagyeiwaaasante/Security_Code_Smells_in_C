/* CWE-401 Memory Leak — good (free before reassign)
 * FIX: free() is called before the pointer is overwritten with a new
 *      allocation.
 */
#include <stdlib.h>

void good_overwrite(int n)
{
    int *data = (int *)malloc((size_t)n * sizeof(int));
    if (data == NULL) { return; }

    free(data);  /* FIX: release first allocation before reassign */
    data = (int *)malloc((size_t)n * 2 * sizeof(int));
    if (data == NULL) { return; }

    data[0] = n;
    free(data);
}
