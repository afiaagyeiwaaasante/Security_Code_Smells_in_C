static void goodG2B()
{
    char * data;
    /* FIX: Initialize data */
    data = "Good";
    /* POTENTIAL FLAW: Attempt to use data, which may be NULL */
    /* printLine() checks for NULL, so we cannot use it here */
    printHexCharLine(data[0]);
}