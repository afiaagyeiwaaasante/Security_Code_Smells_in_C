/* CWE-190 Integer Overflow — bad: C++ constructor/destructor on heap (flow 84)
 * Flow  : data passed to constructor, stored as member, overflow operation in destructor
 *         object allocated on the heap — destructor runs at delete
 * FLAW  : destructor performs data * 2 without bounds check
 */
#include <cstdlib>

class MultiplyContainer {
    int storedData;
public:
    MultiplyContainer(int data) : storedData(data) {}

    ~MultiplyContainer() {
        if (storedData > 0) {
            /* POTENTIAL FLAW: storedData * 2 overflows when storedData > INT_MAX/2 */
            int result = storedData * 2;
            (void)result;
        }
    }
};

void bad_int_multiply_84(void)
{
    int data = rand();
    /* Object on heap — destructor runs at delete */
    MultiplyContainer* obj = new MultiplyContainer(data);
    delete obj;
}
