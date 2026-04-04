#include "../testsuitesupport/std_testcase.h"

class GoodClass {
public:
    char *name;
    GoodClass(const char *n) {
        name = new char[strlen(n)+1];
        strcpy(name, n);
    }
    ~GoodClass() { delete[] name; }
    GoodClass& operator=(const GoodClass& rhs) {
        /* FIX: self-assignment guard prevents UAF */
        if (this != &rhs) {
            delete[] this->name;
            this->name = new char[strlen(rhs.name)+1];
            strcpy(this->name, rhs.name);
        }
        return *this;
    }
};

void good_operator_equals(void)
{
    GoodClass obj("hello");
    obj = obj;
    printLine(obj.name);
}
