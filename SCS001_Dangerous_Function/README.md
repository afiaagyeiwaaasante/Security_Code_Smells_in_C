# SCS001 - Use of Inherently Dangerous Function (CWE 242)

## Description
This security code smell refers to the use of inherently dangerous C standard library functions that are known to be unsafe due to the absence of bounds checking or input validation mechanisms.
These functions can lead to:
- Buffer overflows
- Stack corruption
- Arbitrary code execution
- Denial of service

## Why this is a Problem
Certain legacy C functions do not enforce input size constraints. When used improperly, they allow writing beyond allocated memory boundaries.

## Security Classification 
CWE ID: 242 
Risk Level: High
Category: Memory Safety Violation