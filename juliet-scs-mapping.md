# Juliet — Security Code Smell Mapping

| ID      | Smell Name                   | Category          | Brief Description                                                    | CWE Mapping               | Juliet CWE Mapping   |
|:--------|:-----------------------------|:------------------|:---------------------------------------------------------------------|:--------------------------|:---------------------|
| SCS001  | Dangerous Function Use       | Memory Safety     | Use of gets(), strcpy(), strcat() without bounds checking            | CWE-120, CWE-676, CWE-242 | CWE-242              |
| SCS002  | Buffer Size Mismatch         | Memory Safety     | Buffer allocation size doesn't match usage size                      | CWE-131, CWE-680          | CWE-680              |
| SCS003  | Missing NULL Check           | Memory Safety     | Dereferencing pointer without NULL verification                      | CWE-476, CWE-690          | CWE-476, CWE-690     |
| SCS004  | Use-After-Free Risk          | Memory Safety     | Accessing memory after potential deallocation                        | CWE-416, CWE-672          | CWE-416, CWE-672     |
| SCS005  | Memory Leak Pattern          | Memory Safety     | Allocated memory not freed on all exit paths                         | CWE-401, CWE-772          | CWE-401              |
| SCS006  | Integer Overflow Risk        | Integer Handling  | Arithmetic operation without overflow check                          | CWE-190, CWE-191          | CWE-190, CWE-191     |
| SCS007  | Signed/Unsigned Confusion    | Integer Handling  | Implicit conversion between signed and unsigned types                | CWE-194, CWE-195          | CWE-194, CWE-195     |
| SCS008  | Missing Format Specifier     | Input Validation  | printf/fprintf/syslog called without a format string literal         | CWE-134, CWE-686          | CWE-134              |
| SCS009  | Command Injection Risk       | Input Validation  | Unsanitized input passed to system(), popen(), or execl()            | CWE-78, CWE-88            | CWE-78               |
| SCS010  | Hardcoded Sensitive Data     | API Misuse        | Passwords, keys, or tokens embedded as literals in source code       | CWE-259, CWE-798          | CWE-259              |