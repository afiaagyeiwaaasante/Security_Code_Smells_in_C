
static void good1(int argc)
{
    {
        char dest[DEST_SIZE];
        char *result;
        /* FIX: use fgets for bounded read from stdin*/
        result = fgets(dest, DEST_SIZE, stdin);
        /* Verify return value */
        if (result == NULL)
        {
            /* error condition */
            printLine("Error Condition: alter control flow to indicate action taken");
            exit(1);
        }
        dest[DEST_SIZE-1] = '\0';
        printLine(dest);
    }
}
