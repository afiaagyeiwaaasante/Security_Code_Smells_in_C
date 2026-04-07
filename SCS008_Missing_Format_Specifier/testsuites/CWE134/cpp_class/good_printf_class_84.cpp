/* SCS008 CWE-134 — Missing Format Specifier
 * Group: cpp_class  |  Flow: 84 (C++ class, destructor sink)  — GOOD variant
 * GoodSink: printf("%s\n", data_) in destructor — literal format string
 * FIX: member variable passed as value argument, not format argument
 */
#include <cstdio>
#include <cstring>

class GoodFormatClass {
public:
    char data_[100];

    GoodFormatClass() {
        data_[0] = '\0';
        if (fgets(data_, sizeof(data_), stdin) != NULL) {
            size_t len = strlen(data_);
            if (len > 0 && data_[len - 1] == '\n') data_[len - 1] = '\0';
        }
    }

    ~GoodFormatClass() {
        /* FIX: literal format string — data_ is treated as a value, not a format */
        printf("%s\n", data_);
    }
};

int main(void)
{
    GoodFormatClass obj;
    return 0;
}
