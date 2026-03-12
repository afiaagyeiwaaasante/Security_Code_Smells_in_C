# Juliet- Security Code Smell Mapping 

| ID      | Smell Name                   | Category          | Brief Description                                         | CWE Mapping        | Juliet CWE Mapping |
|:--------|:-----------------------------|:------------------|:----------------------------------------------------------|:-------------------|:-------------------|
| SCS001  | Dangerous Function Use       | Memory Safety     | Use of get(), strcpy(), strcat(), without bounds checking | CWE -120 , CWE-676, CWE 242 | CWE 242            |
| SCS002  | Buffer Size Mismatch         | Memory Safety     | Buffer allocation size doesn't match usage size           | CWE 131 , CWE 680  | CWE 680            |
| SCS003  | Missing NULL Check           | Memory Safety     | Dereferencing pointer without NULL verification           | CWE 476, CWE 690   | CWE 476, CWE 690   |
| SCS004  | Use-After-Free Risk          | Memory Safety     | Accessing memory after potential deallocation             | CWE 416, CWE 672   | CWE 416, CWE 672   |
| SCS005  | Memory Leak Pattern          | Memory safety     | Allocated memory not freed on all paths                   | CWE 401, CWE 772   | CWE 401            |
| SCS006  | Integer Overflow Risk        | Integer Handling  | Arithmetic operation without overflow check               | CWE 190, CWE 191   | CWE 190, CWE 191   |
| SCS007  | Signed/Unsigned Confusion    | Integer Handling  | Implicit conversion between signed/unsigned types         | CWE 194, CWE 195   | CWE 194, CWE 195   |
| SCS008  | Unvalidated User Input       | Input Validation  | External input used without validation                    | CWE 20 , CWE 116   |                    |
| SCS009  | Format String Vulnerability  | Input Validation  | User-controlled format string in printf() family          | CWE 134, CWE 686   | CWE 134            |
| SCS010  | Command Injection Risk       | Input Validation  | Unsanitzed input passed to system commands.               |  CWE 78 , CWE 88   | CWE 78             |
| SCS011  | Incorrect Error Handling     | API Misuse        | Ignoring or mishandling function return values            | CWE 252 , CWE 253  | CWE 252 , CWE 253  |
| SCS012  | Hardcoded Sensitive Data     | API Misuse        | Passwords, keys, or tokens in source code.                | CWE 259 , CWE 798  | CWE 259            |