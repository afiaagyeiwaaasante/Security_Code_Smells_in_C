/* CWE-190 Integer Overflow — good: C++ constructor/destructor on heap (flow 84)
 * Flow  : data passed to constructor, stored as member, operation in destructor
 *         object allocated on the heap — destructor runs at delete
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

void good_int_multiply_84(void)
{
    int data = rand();
    /* Object on heap — destructor runs at delete */
    MultiplyContainer* obj = new MultiplyContainer(data);
    delete obj;
}
