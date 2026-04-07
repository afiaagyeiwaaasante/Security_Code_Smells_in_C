/* CWE-190 Integer Overflow — good: C++ virtual method via reference (flow 81)
 * Flow  : data passed as parameter to a virtual method, called through a reference
 * FIX   : good derived class checks data <= INT_MAX/2 before multiplying
 */
#include <cstdlib>
#include <climits>

class MultiplyBase {
public:
    virtual void action(int data) const = 0;
    virtual ~MultiplyBase() {}
};

class MultiplyGood : public MultiplyBase {
public:
    void action(int data) const override {
        if (data > 0) {
            /* FIX: bounds check prevents overflow */
            if (data <= (INT_MAX / 2)) {
                int result = data * 2;
                (void)result;
            }
        }
    }
};

void good_int_multiply_81(void)
{
    int data = rand();
    const MultiplyBase& obj = MultiplyGood();
    obj.action(data);   /* dispatch via reference — good action runs */
}
