/* CWE-190 Integer Overflow — good: C++ constructor/destructor on stack (flow 83)
 * Flow  : data passed to constructor, stored as member, operation in destructor
 *         object declared on the stack — destructor runs when scope exits
 * FIX   : destructor checks storedData <= INT_MAX/2 before multiplying
 */
#include <cstdlib>
#include <climits>

class MultiplyContainer {
    int storedData;
public:
    MultiplyContainer(int data) : storedData(data) {}

    ~MultiplyContainer() {
        if (storedData > 0) {
            /* FIX: bounds check in destructor prevents overflow */
            if (storedData <= (INT_MAX / 2)) {
                int result = storedData * 2;
                (void)result;
            }
        }
    }
};

void good_int_multiply_83(void)
{
    int data = rand();
    /* Object on stack — destructor runs at end of this scope */
    MultiplyContainer obj(data);
    (void)obj;
}
