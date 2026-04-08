/* bad_password_class_84.cpp
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * BAD: C++ class constructor assigns a hardcoded string literal to a
 * member variable named 'password_'.
 * Juliet basis: CWE259_Hard_Coded_Password__w32_char_84 (adapted, cross-platform)
 */
#include <cstdio>
#include <cstring>

class BadAuthClass
{
public:
    char password_[64];

    BadAuthClass()
    {
        /* FLAW: hardcoded password literal copied into member */
        strcpy(password_, "ABCD1234!");
    }

    bool authenticate(const char *input) const
    {
        return strcmp(input, password_) == 0;
    }
};

int main(void)
{
    BadAuthClass auth;

    char buf[64];
    if (std::fgets(buf, sizeof(buf), stdin) == nullptr)
        return 1;
    buf[std::strcspn(buf, "\n")] = '\0';

    std::puts(auth.authenticate(buf) ? "Access granted." : "Access denied.");
    return 0;
}
