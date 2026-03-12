# SCS002 - Buffer Size Mismatch (CWE 680)

## Description
This smell occurs when a memory allocation function (malloc, calloc, realloc) is called with an incorrect size, typically due to misuse of sizeof:

- Using sizeof(pointer) instead of sizeof(*pointer) or sizeof(type)
- Allocating fewer bytes than intended
- Can lead to buffer overflows, heap corruption, or undefined behavior

Buffer overflow = > relies on external data to control its behavior or depends on properties of the data that are enforced outside of the immediate scope of the code.

## Security Classification 
CWE ID: 680
Risk Level: High
Category: Memory Safety Violation