/* CWE-190 Integer Overflow — bad: C++ virtual method via pointer (flow 82)
 * Flow  : data passed as parameter to a virtual method, called through a pointer
 * FLAW  : bad derived class performs data * 2 without bounds check
 */
#include <cstdlib>
#include <climits>

class MultiplyBase {
public:
    virtual void action(int data) const = 0;
    virtual ~MultiplyBase() {}
};

class MultiplyBad : public MultiplyBase {
public:
    void action(int data) const override {
        if (data > 0) {
            /* POTENTIAL FLAW: data * 2 overflows when data > INT_MAX/2 */
            int result = data * 2;
            (void)result;
        }
    }
};

void bad_int_multiply_82(void)
{
    int data = rand();
    MultiplyBase* obj = new MultiplyBad();
    obj->action(data);  /* dispatch via pointer — bad action runs */
    delete obj;
}
