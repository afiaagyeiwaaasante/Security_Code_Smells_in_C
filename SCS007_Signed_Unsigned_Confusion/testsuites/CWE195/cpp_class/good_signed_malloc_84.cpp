/* CWE-195 Signed-to-Unsigned Conversion Error — good: C++ ctor/dtor on heap (flow 84)
 * Flow  : signed data read in constructor, stored as member, malloc in destructor
 *         object allocated on the heap — destructor runs at delete
 * FIX   : destructor checks storedData > 0 before calling malloc
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>

class SizeContainer {
    int storedData;
public:
    SizeContainer(int data) : storedData(data)
    {
        fscanf(stdin, "%d", &storedData);
    }

    ~SizeContainer()
    {
        /* FIX: positivity check guards the signed-to-unsigned conversion */
        if (storedData > 0 && storedData < 100)
        {
            char *buf = (char *)malloc(storedData);
            if (buf == NULL) { return; }
            memset(buf, 'A', storedData - 1);
            buf[storedData - 1] = '\0';
            free(buf);
        }
    }
};

void good_signed_malloc_84(void)
{
    int data = -1;
    SizeContainer *obj = new SizeContainer(data);
    delete obj;
}
