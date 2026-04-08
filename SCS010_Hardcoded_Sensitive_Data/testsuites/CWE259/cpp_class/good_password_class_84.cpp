/* good_password_class_84.cpp
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * GOOD: C++ class constructor reads the password from the environment
 * at runtime — no hardcoded literal.
 * Juliet basis: CWE259_Hard_Coded_Password__w32_char_84 goodG2B (adapted)
 */
#include <cstdio>
#include <cstring>
#include <cstdlib>

class GoodAuthClass
{
public:
    char password_[64];

    GoodAuthClass()
    {
        /* FIX: password read from environment at runtime */
        const char *env = std::getenv("APP_PASSWORD");
        if (env != nullptr)
            std::strncpy(password_, env, sizeof(password_) - 1);
        else
            password_[0] = '\0';
    }

    bool authenticate(const char *input) const
    {
        return std::strcmp(input, password_) == 0;
    }
};

int main(void)
{
    GoodAuthClass auth;

    char buf[64];
    if (std::fgets(buf, sizeof(buf), stdin) == nullptr)
        return 1;
    buf[std::strcspn(buf, "\n")] = '\0';

    std::puts(auth.authenticate(buf) ? "Access granted." : "Access denied.");
    return 0;
}
