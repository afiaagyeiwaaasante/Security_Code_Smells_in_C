/* CWE-401 Memory Leak — good (malloc with free)
 * FIX: every return path frees the allocated memory.
 */
#include <stdlib.h>

void good_malloc_with_free(int n)
{
    int *data = (int *)malloc((size_t)n * sizeof(int));
    if (data == NULL) { return; }

    data[0] = 1;
    free(data);  /* FIX: always freed before return */
}
