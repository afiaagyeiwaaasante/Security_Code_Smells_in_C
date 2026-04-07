/* CWE-195 Signed-to-Unsigned Conversion Error — bad: C++ ctor/dtor on heap (flow 84)
 * Flow  : signed data read in constructor, stored as member, malloc in destructor
 *         object allocated on the heap — destructor runs at delete
 * FLAW  : destructor calls malloc(storedData) with no positivity check
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>

class SizeContainer {
    int storedData;
public:
    SizeContainer(int data) : storedData(data)
    {
        /* POTENTIAL FLAW: read signed int from stdin into member — may be negative */
        fscanf(stdin, "%d", &storedData);
    }

    ~SizeContainer()
    {
        if (storedData < 100)
        {
            /* POTENTIAL FLAW: storedData may be negative — wraps to huge size_t */
            char *buf = (char *)malloc(storedData);
            if (buf == NULL) { return; }
            memset(buf, 'A', storedData - 1);
            buf[storedData - 1] = '\0';
            free(buf);
        }
    }
};

void bad_signed_malloc_84(void)
{
    int data = -1;
    SizeContainer *obj = new SizeContainer(data);
    delete obj;
}
