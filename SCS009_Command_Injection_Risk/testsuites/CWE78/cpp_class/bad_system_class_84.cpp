/* bad_system_class_84.cpp
 * CWE-78 Command Injection Risk — SCS009
 * BAD: ctor reads user input (fgets) into a member; dtor calls system() with it.
 * NOTE: Our detector splits on function/destructor blocks separately, so the
 *       fgets (in ctor) and system() (in dtor) are in DIFFERENT blocks —
 *       KNOWN FALSE NEGATIVE (cross-block taint within a class).
 * Juliet basis: CWE78_OS_Command_Injection__char_console_system_84
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define BUFSIZE 256

class BadCommandClass
{
public:
    char data_[BUFSIZE];

    BadCommandClass()
    {
        /* Source: console (fgets) — stored in member for dtor to use */
        if (fgets(data_, BUFSIZE, stdin) != NULL)
            data_[strcspn(data_, "\n")] = '\0';
    }

    ~BadCommandClass()
    {
        /* BAD: member data_ came from fgets in ctor — tainted */
        system(data_);
    }
};

int main(void)
{
    BadCommandClass obj;
    return 0;
}
