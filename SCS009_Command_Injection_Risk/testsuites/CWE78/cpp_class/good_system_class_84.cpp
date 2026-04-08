/* good_system_class_84.cpp
 * CWE-78 Command Injection Risk — SCS009
 * GOOD: dtor calls system() with a hard-coded string literal, not member data.
 * Juliet basis: CWE78_OS_Command_Injection__char_console_system_84 (goodG2B)
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define BUFSIZE 256

class GoodCommandClass
{
public:
    char data_[BUFSIZE];

    GoodCommandClass()
    {
        /* Source: console (fgets) — read but not forwarded to system() */
        if (fgets(data_, BUFSIZE, stdin) != NULL)
            data_[strcspn(data_, "\n")] = '\0';
    }

    ~GoodCommandClass()
    {
        /* GOOD: system() receives a fixed literal */
        system("ls -l");
    }
};

int main(void)
{
    GoodCommandClass obj;
    return 0;
}
