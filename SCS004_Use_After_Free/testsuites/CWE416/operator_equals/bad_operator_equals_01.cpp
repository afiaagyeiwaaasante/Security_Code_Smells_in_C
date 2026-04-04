#include "../testsuitesupport/std_testcase.h"

class BadClass {
public:
    char *name;
    BadClass(const char *n) {
        name = new char[strlen(n)+1];
        strcpy(name, n);
    }
    ~BadClass() { delete[] name; }
    BadClass& operator=(const BadClass& rhs) {
        /* FLAW: no self-assignment check — if rhs is *this,
           delete[] frees name before strlen(rhs.name) reads it */
        delete[] this->name;
        this->name = new char[strlen(rhs.name)+1];
        strcpy(this->name, rhs.name);
        return *this;
    }
};

void bad_operator_equals(void)
{
    BadClass obj("hello");
    obj = obj;  /* triggers self-assignment UAF */
    printLine(obj.name);
}
