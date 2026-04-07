/* CWE-190 Integer Overflow — bad: C++ constructor/destructor on stack (flow 83)
 * Flow  : data passed to constructor, stored as member, overflow operation in destructor
 *         object declared on the stack — destructor runs when scope exits
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

void bad_int_multiply_83(void)
{
    int data = rand();
    /* Object on stack — destructor runs at end of this scope */
    MultiplyContainer obj(data);
    (void)obj;
}
