# SCS003 - Missing Null Check (CWE 476 & CWE 690)

## Description
 This smell occurs when a pointer with a value of NULL is used as though it pointed to a valid memory area. 

 These functions may return NULL on failure, omitting an explicit NULL check can lead to NULL pointer dereference, or program crashes.

## Security Classification 
CWE ID: 476 & 680
Risk Level: High
Category: Memory Safety Violation