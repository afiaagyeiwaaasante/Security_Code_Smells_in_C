/* CWE-190 Integer Overflow — bad: interprocedural add, sink file (22b)
 * Flow: receives data from bad_int_add_22a; adds 1 without check.
 * FLAW: no bounds check before data + 1 — overflows when data == INT_MAX.
 */
void bad_int_add_22b_sink(int data)
{
    /* POTENTIAL FLAW: data + 1 overflows when data == INT_MAX */
    int result = data + 1;
    (void)result;
}
