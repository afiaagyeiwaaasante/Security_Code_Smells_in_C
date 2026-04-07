/* CWE-401 Memory Leak — good (free on all return paths)
 * FIX: every early return is preceded by a free() call.
 */
#include <stdlib.h>

int good_early_return(int n)
{
    int *data = (int *)malloc((size_t)n * sizeof(int));
    if (data == NULL) { return -1; }

    if (n < 0) {
        free(data);  /* FIX: free before early return */
        return -1;
    }

    data[0] = n;
    free(data);
    return 0;
}
