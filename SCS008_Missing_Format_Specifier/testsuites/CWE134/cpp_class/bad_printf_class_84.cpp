/* SCS008 CWE-134 — Missing Format Specifier
 * Group: cpp_class  |  Flow: 84 (C++ class, destructor sink)
 * BadSource: fgets into member variable in constructor
 * BadSink  : printf(data_) in destructor — member used directly as format
 * FLAW: user input stored as member, later used as printf format without literal
 */
#include <cstdio>
#include <cstring>

class BadFormatClass {
public:
    char data_[100];

    BadFormatClass() {
        data_[0] = '\0';
        /* FLAW: read user input into member — will be used as format later */
        if (fgets(data_, sizeof(data_), stdin) != NULL) {
            size_t len = strlen(data_);
            if (len > 0 && data_[len - 1] == '\n') data_[len - 1] = '\0';
        }
    }

    ~BadFormatClass() {
        /* FLAW: member variable used directly as format argument */
        printf(data_);
    }
};

int main(void)
{
    BadFormatClass obj;
    return 0;
}
