# Using srcType for Security Code Smell Detection

`srcType` will be used to extract **static type information from C programs**.  
This information is necessary for detecting certain **security code smells** that cannot be reliably identified using syntax analysis alone.

For this research, `srcType` should support extraction of the following type information:

- Pointer types
- Signed vs unsigned integer types
- Typedef resolution (e.g., `size_t`, `uint32_t`)

The extracted type information will be used to detect **type-related security code smells**.

---

# 1. Pointer Type Detection

`srcType` should identify when a variable is declared as a **pointer type**.

This information is needed to detect situations where a pointer is **used without checking whether it is NULL**, which may lead to **NULL pointer dereference**.

## Example

```c
void example() {
    char *buffer = malloc(100);

    buffer[0] = 'A';   // used without NULL check
}
```
#### Expected Information from srcType 
Variable: buffer
Type: char *
Category: pointer

# 2. Signed vs Unsigned Type Detection 
'srcType' should identify whether a variable is signed or unsigned.
 
 This is neccessary for detecting comparisons between signed and unsigned values, which can cause unexpected behavior due to implicit type conversion.

 ## Example 
 ```c 
 void check(int length, size_t buffer_size){
    if(length < buffer_size){
        printf("Safe\n");
    }
 }
 ```

 ### Expected Information from srcType 
 Variable: length 
 Type: int 
 Category: signed 

 Variable: buffer_size
 Type: size_int
 Category: unsigned 


 # 3. Typedef Resolution 
 'srcType'  should resolve typedef types to their underlying type to their underlying types 

 ## Example 
 size_t -> unsigned integer type
 uint32_t -> unsigned integer type.